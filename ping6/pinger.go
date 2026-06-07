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

	conn *net.IPConn
	fd   int
	f    *os.File // duplicated fd file, kept open for TX timestamp + option lifetime

	supportTxTS bool
	supportRxTS bool

	connOnce sync.Once
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
	conn, err := p.openConn()
	if err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}
	p.conn = conn
	defer p.connOnce.Do(func() { _ = conn.Close() })

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

// openConn opens a raw IPv6 ICMP socket and configures hardware timestamping.
func (p *Pinger) openConn() (*net.IPConn, error) {
	local := p.conf.LocalAddr
	if local == "" {
		local = "::"
	}

	conn, err := net.ListenPacket("ip6:ipv6-icmp", local)
	if err != nil {
		return nil, err
	}

	ipconn := conn.(*net.IPConn)
	// conn.File() dups the fd — keep the *os.File alive so the fd is usable.
	f, err := ipconn.File()
	if err != nil {
		return nil, err
	}
	p.f = f
	p.fd = int(f.Fd())

	if p.conf.Hwts {
		if err := configureTimestamps(p.fd, p.conf.Interface, p.conf.Verbose, p.logger, &p.supportTxTS, &p.supportRxTS); err != nil {
			return nil, err
		}
	}

	// Set socket timeouts.
	if err := setSocketTimeouts(p.fd, p.conf.Timeout); err != nil {
		return nil, err
	}

	return ipconn, nil
}

// buildICMPv6Pkt constructs an ICMPv6 Echo Request packet and returns the wire-format bytes.
func (p *Pinger) buildICMPv6Pkt(t *target, seq uint16, payload []byte) ([]byte, error) {
	echoBody := layers.NewICMPv6Echo(t.icmpID, seq)
	echoBody.Set("data", payload)

	ipv6 := layers.NewIPv6()
	ipv6.Set("src", p.conf.LocalAddr)
	ipv6.Set("dst", t.addr)
	ipv6.Set("hlim", uint8(p.conf.HopLimit))
	if p.conf.TC > 0 {
		ipv6.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(uint8(p.conf.TC), 0))
	}

	icmpHdr := layers.NewICMPv6()
	icmpHdr.Set("type", layers.ICMPv6EchoRequest)

	pkt := packet.NewFrom(ipv6, icmpHdr, echoBody)

	// Build from layer 1 (ICMPv6) onwards — the kernel adds the IPv6 header for
	// ip6:ipv6-icmp raw sockets (IPPROTO_ICMPV6).
	return pkt.BuildFrom(1)
}

// serveSend is the main send loop. It sends ICMPv6 Echo Requests to all targets
// at the configured rate.
func (p *Pinger) serveSend(ctx context.Context, stopCh chan struct{}) error {
	defer p.connOnce.Do(func() {
		_ = p.conn.Close()
		_ = p.f.Close()
	})

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

			data, err := p.buildICMPv6Pkt(t, seq, sendPayload)
			if err != nil {
				p.logger.Printf("[ERRO] build packet for %s: %v", t.addr, err)
				continue
			}

			ra := &net.IPAddr{IP: t.ip}
			if _, err := p.conn.WriteTo(data, ra); err != nil {
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
	defer p.connOnce.Do(func() {
		_ = p.conn.Close()
		_ = p.f.Close()
	})

	pktBuf := make([]byte, 1500)
	oob := make([]byte, 1500)

	for {
		select {
		case <-stopCh:
			return nil
		default:
		}

		n, oobn, _, ra, err := p.conn.ReadMsgIP(pktBuf, oob)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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

		p.processPacket(pktBuf[:n], ra, rxts)
	}
}

// processPacket parses raw IPv6 packet bytes and routes to the appropriate handler.
func (p *Pinger) processPacket(raw []byte, ra net.Addr, rxts int64) {
	// On macOS, ReadMsgIP for ip6:ipv6-icmp may or may not include the IPv6
	// header. Try IPv6 first, fall back to ICMPv6.
	pkt, err := packet.DissectByProto(raw, "IPv6")
	if err != nil {
		pkt, err = packet.DissectByProto(raw, "ICMPv6")
		if err != nil {
			return
		}
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
		p.handleEchoReply(pkt, ra, rxts)
	case icmpv6DestUnreach, icmpv6TimeExceed:
		srcStr := addrString(ra)
		p.handleICMPv6Error(srcStr, icmpType)
	}
}

// handleEchoReply processes an ICMPv6 Echo Reply packet.
// ra is the remote address from ReadMsgIP, used as the reply source.
func (p *Pinger) handleEchoReply(pkt *packet.Packet, ra net.Addr, rxts int64) {
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
	srcStr := addrString(ra)
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

	// Try to get hop limit from IPv6 layer (if present).
	var hlim uint8
	if ipv6Layer := pkt.GetLayer("IPv6"); ipv6Layer != nil {
		if hlimVal, err := ipv6Layer.Get("hlim"); err == nil && hlimVal != nil {
			hlim, _ = hlimVal.(uint8)
		}
	}

	// Per-reply output (only when verbose).
	if p.conf.Verbose {
		rttMs := float64(rtt) / float64(time.Millisecond)
		p.logger.Printf("[INFO] %d bytes from %s: icmp_seq=%d hlim=%d time=%.3fms",
			payloadLen, t.addr, icmpSeq, hlim, rttMs)
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

// addrString extracts the IP address string from a net.Addr.
func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	default:
		return addr.String()
	}
}
