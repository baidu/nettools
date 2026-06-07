package ping6

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/baidu/nettools/stat"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"go.uber.org/ratelimit"
)

const (
	icmpv6EchoReply   = 129
	icmpv6DestUnreach = 1
	icmpv6TimeExceed  = 3

	// timestampLen is the size of the embedded send timestamp (8 bytes, little-endian int64).
	timestampLen = 8
)

// target holds per-destination state for a ping target.
type target struct {
	addr   string
	ip     net.IP
	icmpID uint16 // unique ICMP identifier for this target
	stat   stat.Stat
	seq    uint64 // monotonically increasing sequence counter
}

// Pinger sends ICMPv6 Echo Requests to one or more targets and collects
// per-target statistics (sent, received, loss rate, latency).
type Pinger struct {
	conf    *Config
	limiter ratelimit.Limiter
	logger  *log.Logger

	targets []*target
	pid     uint16

	fd int
	f  *os.File // keeps fd alive for timestamp options

	supportTxTS bool
	supportRxTS bool

	closeOnce sync.Once
}

// NewPinger creates a Pinger with the given configuration, rate limiter, and logger.
func NewPinger(conf *Config, limiter ratelimit.Limiter, logger *log.Logger) *Pinger {
	pid := uint16(os.Getpid() & 0xFFFF)

	targets := make([]*target, 0, len(conf.TargetAddrs))
	for i, addr := range conf.TargetAddrs {
		// Each target gets a unique ICMP ID: base pid + target index (wrapped at 16 bits).
		icmpID := pid + uint16(i)
		targets = append(targets, &target{
			addr:   addr,
			ip:     net.ParseIP(addr),
			icmpID: icmpID,
		})
	}

	return &Pinger{
		conf:    conf,
		limiter: limiter,
		logger:  logger,
		targets: targets,
		pid:     pid,
	}
}

// Run starts the pinger: opens raw sockets, launches send and receive goroutines,
// and blocks until the context is cancelled or a send limit is reached.
func (p *Pinger) Run(ctx context.Context) error {
	if err := p.openConn(); err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}
	defer p.closeOnce.Do(func() { _ = p.f.Close() })

	p.logger.Printf("[INFO] pinging (local: %s, pid: %d, rate: %d pps, interface: %s)",
		p.conf.LocalAddr, p.pid, p.conf.Rate, p.conf.Interface)
	for _, t := range p.targets {
		p.logger.Printf("[INFO] target %s (icmp_id=%d)", t.addr, t.icmpID)
	}

	// Set up per-target stat instances.
	proc := stat.NewProcessor(p.conf.Span, p.conf.Delay)
	logSender := stat.NewLogSender(p.logger, p.conf.Verbose)
	dummyPort := stat.PortRange{Min: 0, Max: 0}

	for _, t := range p.targets {
		s := stat.NewStat(p.conf.LocalAddr, t.addr, dummyPort, dummyPort, p.conf.Rate, p.conf.Span, p.conf.Delay, logSender)
		proc.AddStat(s)
		t.stat = s
		t.seq = uint64(rand.Int63())
	}

	stopCh := make(chan struct{})
	done := make(chan error, 2)

	go func() {
		done <- p.serveRecv(stopCh)
	}()
	go proc.Run(ctx)

	go func() {
		done <- p.serveSend(ctx, stopCh)
	}()

	return <-done
}

// openConn creates a SOCK_DGRAM ICMPv6 socket.
// On macOS, SOCK_DGRAM+IPPROTO_ICMPV6 is required because SOCK_RAW sockets
// do not receive ICMPv6 Echo Replies (the kernel processes them internally).
func (p *Pinger) openConn() error {
	ip := net.ParseIP(p.conf.LocalAddr)
	if ip == nil {
		ip = net.IPv6unspecified
	}

	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}

	// Bind to local address.
	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[:], ip.To16())
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}

	p.fd = fd
	p.f = os.NewFile(uintptr(fd), "icmp6")

	if p.conf.Hwts {
		if err := configureTimestamps(p.fd, p.conf.Interface, p.conf.Verbose, p.logger, &p.supportTxTS, &p.supportRxTS); err != nil {
			_ = syscall.Close(fd)
			return err
		}
	}

	// Set socket timeouts.
	if err := setSocketTimeouts(p.fd, p.conf.Timeout); err != nil {
		_ = syscall.Close(fd)
		return err
	}

	return nil
}

// buildICMPv6Echo constructs the ICMPv6 Echo Request body (id + seq + data).
// With SOCK_DGRAM+IPPROTO_ICMPV6, the kernel adds the ICMPv6 header (type, code,
// checksum) and the IPv6 header. We only provide the Echo body.
func (p *Pinger) buildICMPv6Echo(t *target, seq uint16, payload []byte) ([]byte, error) {
	// Build just the ICMPv6 Echo layer: id(2) + seq(2) + data(variable).
	// The kernel will prepend ICMPv6 header (type=128, code=0, checksum).
	echoBody := layers.NewICMPv6Echo(t.icmpID, seq)
	echoBody.Set("data", payload)

	buf := make([]byte, echoBody.WireSize())
	n, err := echoBody.SerializeInto(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// serveSend is the main send loop. It sends ICMPv6 Echo Requests to all targets
// at the configured rate.
func (p *Pinger) serveSend(ctx context.Context, stopCh chan struct{}) error {
	defer p.closeOnce.Do(func() { _ = p.f.Close() })

	randPayload := make([]byte, p.conf.Size-timestampLen)
	_, _ = cryptorand.Read(randPayload)

	var count int
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			close(stopCh)
			time.Sleep(p.conf.Delay)
			return nil
		default:
		}

		if p.conf.Count > 0 && count >= p.conf.Count {
			close(stopCh)
			time.Sleep(p.conf.Delay)
			return nil
		}
		if p.conf.SendDuration > 0 && time.Since(startTime) >= p.conf.SendDuration {
			close(stopCh)
			time.Sleep(p.conf.Delay)
			return nil
		}

		p.limiter.Take()

		for _, t := range p.targets {
			t.seq++
			seq := uint16(t.seq & 0xFFFF)
			now := time.Now().UnixNano()

			// Build payload: timestamp (8 bytes LE) + random padding.
			sendPayload := make([]byte, p.conf.Size)
			binary.LittleEndian.PutUint64(sendPayload[:timestampLen], uint64(now))
			copy(sendPayload[timestampLen:], randPayload)

			data, err := p.buildICMPv6Echo(t, seq, sendPayload)
			if err != nil {
				p.logger.Printf("[ERRO] build packet for %s: %v", t.addr, err)
				continue
			}

			ra := &syscall.SockaddrInet6{}
			copy(ra.Addr[:], t.ip.To16())
			if err := syscall.Sendmsg(p.fd, data, nil, ra, 0); err != nil {
				p.logger.Printf("[ERRO] send to %s: %v", t.addr, err)
				continue
			}

			// Try to get TX hardware timestamp.
			if p.supportTxTS {
				if txts, err := getTxTimestamp(p.fd); err == nil {
					now = txts
				}
			}

			t.stat.Put(0, 0, uint64(seq), now)
			count++
		}
	}
}

// serveRecv reads raw packets from the ICMPv6 socket and processes them.
func (p *Pinger) serveRecv(stopCh <-chan struct{}) error {
	defer p.closeOnce.Do(func() { _ = p.f.Close() })

	pktBuf := make([]byte, 1500)
	oob := make([]byte, 1500)

	for {
		select {
		case <-stopCh:
			return nil
		default:
		}

		n, oobn, _, from, err := syscall.Recvmsg(p.fd, pktBuf, oob, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			if isTimeout(err) {
				continue
			}
			return err
		}

		var rxts int64
		if p.supportRxTS {
			if ts, err := getTimestampFromOOB(oob, oobn); err == nil {
				rxts = ts
			}
		}

		if rxts == 0 {
			rxts = time.Now().UnixNano()
		}

		p.processPacket(pktBuf[:n], from, rxts)
	}
}

// processPacket parses raw ICMPv6 packet bytes and routes to the appropriate handler.
// With SOCK_DGRAM, data starts at the ICMPv6 header (kernel strips IPv6 header).
func (p *Pinger) processPacket(raw []byte, from syscall.Sockaddr, rxts int64) {
	pkt, err := packet.DissectByProto(raw, "ICMPv6")
	if err != nil {
		return
	}

	icmpLayer := pkt.GetLayer("ICMPv6")
	if icmpLayer == nil {
		return
	}

	icmpTypeVal, err := icmpLayer.Get("type")
	if err != nil {
		return
	}
	icmpType, ok := icmpTypeVal.(uint8)
	if !ok {
		return
	}

	switch icmpType {
	case icmpv6EchoReply:
		p.handleEchoReply(pkt, from, rxts)
	case icmpv6DestUnreach, icmpv6TimeExceed:
		srcStr := sockaddrToString(from)
		p.handleICMPv6Error(srcStr, icmpType)
	}
}

// handleEchoReply processes an ICMPv6 Echo Reply packet.
func (p *Pinger) handleEchoReply(pkt *packet.Packet, from syscall.Sockaddr, rxts int64) {
	// The "ICMPv6 Echo Reply" sub-layer has id and seq.
	echoLayer := pkt.GetLayer("ICMPv6 Echo Reply")
	if echoLayer == nil {
		return
	}

	idVal, err := echoLayer.Get("id")
	if err != nil {
		return
	}
	icmpID, ok := idVal.(uint16)
	if !ok {
		return
	}

	// Find target by ICMP ID.
	t := p.findTargetByICMPID(icmpID)
	if t == nil {
		return
	}

	// Verify the reply came from the expected target.
	srcStr := sockaddrToString(from)
	srcIP := net.ParseIP(srcStr)
	if srcIP == nil || !srcIP.Equal(t.ip) {
		return
	}

	seqVal, err := echoLayer.Get("seq")
	if err != nil {
		return
	}
	icmpSeq, ok := seqVal.(uint16)
	if !ok {
		return
	}

	// Extract send timestamp from ICMP payload.
	var sendTS int64
	var payloadLen int
	dataVal, err := echoLayer.Get("data")
	if err == nil {
		if data, ok := dataVal.([]byte); ok {
			payloadLen = len(data)
			if payloadLen >= timestampLen {
				sendTS = int64(binary.LittleEndian.Uint64(data[:timestampLen]))
			}
		}
	}

	rtt := rxts - sendTS
	if sendTS == 0 {
		rtt = 0
	}

	// Per-reply output (only when verbose).
	if p.conf.Verbose {
		rttMs := float64(rtt) / float64(time.Millisecond)
		p.logger.Printf("[INFO] %d bytes from %s: icmp_seq=%d time=%.3fms",
			payloadLen, t.addr, icmpSeq, rttMs)
	}

	t.stat.Received(uint64(icmpSeq), rxts, rtt, false)
}

// handleICMPv6Error logs ICMPv6 destination unreachable or time exceeded messages.
func (p *Pinger) handleICMPv6Error(srcStr string, icmpType uint8) {
	switch icmpType {
	case icmpv6DestUnreach:
		p.logger.Printf("[WARN] destination unreachable from %s", srcStr)
	case icmpv6TimeExceed:
		p.logger.Printf("[WARN] time exceeded from %s", srcStr)
	}
}

// findTargetByICMPID finds the target with the given ICMP identifier.
func (p *Pinger) findTargetByICMPID(icmpID uint16) *target {
	for _, t := range p.targets {
		if t.icmpID == icmpID {
			return t
		}
	}
	return nil
}

// sockaddrToString extracts the IP address string from a syscall.Sockaddr.
func sockaddrToString(sa syscall.Sockaddr) string {
	if sa == nil {
		return ""
	}
	switch s := sa.(type) {
	case *syscall.SockaddrInet6:
		return net.IP(s.Addr[:]).String()
	case *syscall.SockaddrInet4:
		return net.IP(s.Addr[:]).String()
	}
	return ""
}

// isTimeout checks if the error is a timeout-related error.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
