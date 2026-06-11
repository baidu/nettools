// Package agent implements the EVR VXLAN-based probe.
//
// The agent sends UDP/VXLAN packets to a list of EVR VTEPs. Each probe
// carries an inner Ethernet/IPv4/UDP frame whose inner src/dst IP both
// equal the local probing machine's address; the actual EVR src IP is
// embedded in the payload so the response can be matched back to the
// originating target. Statistics are tracked per-target via the shared
// stat package.
package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"go.uber.org/ratelimit"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"github.com/baidu/nettools/evr/codec"
	"github.com/baidu/nettools/evr/config"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"
)

// peer holds per-target probe state.
type peer struct {
	target config.Target

	// outer
	mockSrcIP net.IP
	srcIP     net.IP
	dstIP     net.IP
	srcPort   atomic.Uint32 // packed as uint32 for atomic load/store
	dstPort   uint16

	// inner
	innerSrcIP net.IP
	innerDstIP net.IP

	seq    uint64
	msgLen int

	stat stat.Stat
}

// Agent runs the probe loop for one or more EVR targets.
type Agent struct {
	conf    *config.Config
	limiter ratelimit.Limiter
	proc    *stat.Processor
	logger  *log.Logger
	sender  stat.Sender

	peers []*peer
	// peerByEVRSrc maps inner-src-IP string -> peer for response matching.
	peerByEVRSrc map[string]*peer
	salts        *util.Salts

	// listenPacket is overridable for tests.
	listenPacket func(network, address string) (net.PacketConn, error)
	rconns       []net.PacketConn
}

// New creates an Agent. If sender is nil a stat.LogSender writing to
// logger is used.
func New(conf *config.Config, limiter ratelimit.Limiter, proc *stat.Processor, sender stat.Sender, logger *log.Logger) *Agent {
	if sender == nil {
		sender = stat.NewLogSender(logger, conf.Verbose)
	}
	a := &Agent{
		conf:         conf,
		limiter:      limiter,
		proc:         proc,
		logger:       logger,
		sender:       sender,
		peerByEVRSrc: make(map[string]*peer),
		listenPacket: net.ListenPacket,
	}
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}
	a.salts = util.NewSalts(conf.MsgLen - codec.MsgHeaderLen)
	a.initPeers()
	return a
}

func (a *Agent) initPeers() {
	for _, t := range a.conf.Targets {
		t := t
		mockSrc := t.MockSrcAddr
		if mockSrc == "" {
			mockSrc = a.conf.ClientAddr
		}
		p := &peer{
			target:     t,
			mockSrcIP:  net.ParseIP(mockSrc).To4(),
			srcIP:      net.ParseIP(a.conf.ClientAddr).To4(),
			dstIP:      net.ParseIP(t.VTEPAddr).To4(),
			dstPort:    a.conf.DstPort,
			innerSrcIP: net.ParseIP(t.EVRSrcAddr).To4(),
			// Inner dst IP equals the local machine — the EVR reflects
			// the inner frame back to our probe socket.
			innerDstIP: net.ParseIP(a.conf.ClientAddr).To4(),
			seq:        uint64(rand.Int63()),
			msgLen:     a.conf.MsgLen,
		}
		p.srcPort.Store(uint32(a.conf.ClientPortRange.Min))

		// Reuse the existing per-pair stat: use ClientAddr as the "client"
		// label and EVRSrcAddr as the "server" label so reports identify
		// the target by its EVR src IP.
		s := stat.NewStat(a.conf.ClientAddr, t.EVRSrcAddr,
			a.conf.ClientPortRange, a.conf.ClientPortRange,
			a.conf.RateInSpan, a.conf.Span, a.conf.Delay, a.sender)
		a.proc.AddStat(s)
		p.stat = s

		a.peers = append(a.peers, p)
		a.peerByEVRSrc[t.EVRSrcAddr] = p
		a.logger.Printf("[INFO] configured peer: vtep=%s evr_src=%s mock_src=%s seq=%d",
			t.VTEPAddr, t.EVRSrcAddr, mockSrc, p.seq)
	}
}

// Run starts the read goroutines and enters the send loop. It blocks
// until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.serveRead(); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return a.serveWrite(ctx)
}

func setupRawConn(conn net.PacketConn, tos int, bpfInst []bpf.Instruction) {
	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		return
	}
	_ = ipConn.SetReadBuffer(20 * 1024 * 1024)
	_ = ipConn.SetWriteBuffer(20 * 1024 * 1024)
	pconn := ipv4.NewPacketConn(conn)
	if len(bpfInst) > 0 {
		if assembled, err := bpf.Assemble(bpfInst); err == nil {
			_ = pconn.SetBPF(assembled)
		}
	}
	_ = pconn.SetTOS(tos)
}

func (a *Agent) serveWrite(ctx context.Context) error {
	conn, err := a.listenPacket("ip4:udp", a.conf.ClientAddr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	defer a.closeReadConns()

	setupRawConn(conn, a.conf.TOS, emptyBPF())

	// We build the outer IPv4 header ourselves so we can spoof the source
	// IP (mockSrcAddr) and set the IP-level TOS/TTL. NewRawConn enables
	// IP_HDRINCL so the kernel does not prepend its own IP header.
	rc, err := ipv4.NewRawConn(conn)
	if err != nil {
		return err
	}

	a.logger.Printf("[INFO] EVR probe started: tos=%d span=%v rate=%d targets=%d",
		a.conf.TOS, a.conf.Span, a.conf.RateInSpan, len(a.peers))

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		a.limiter.Take()

		for _, p := range a.peers {
			bizSeq := atomic.AddUint64(&p.seq, 1)
			oldPort := uint16(p.srcPort.Load())
			newPort := config.GetNextPort(oldPort, a.conf.ClientPortRange)
			p.srcPort.Store(uint32(newPort))

			ts := time.Now().UnixNano()
			innerSrcIPNum := binary.BigEndian.Uint32(p.innerSrcIP)
			payload := codec.EncodeWithSrcIP(bizSeq, a.salts.Get(bizSeq), ts, p.msgLen, innerSrcIPNum)

			inner, err := codec.EncodeVxlanInner(a.conf.VNI, a.conf.SrcMAC, a.conf.DstMAC,
				p.innerDstIP, p.innerDstIP, // inner src == inner dst == local IP
				newPort, a.conf.InnerDstPort, uint8(a.conf.TOS), a.conf.TTL, payload)
			if err != nil {
				a.logger.Printf("[ERRO] encode inner: %v", err)
				continue
			}
			data, err := codec.EncodeOuterUDP(p.mockSrcIP, p.dstIP, newPort, p.dstPort,
				uint8(a.conf.TOS), a.conf.TTL, inner)
			if err != nil {
				a.logger.Printf("[ERRO] encode outer: %v", err)
				continue
			}

			p.stat.Put(newPort, p.dstPort, bizSeq, ts)
			if err := rc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				p.stat.Delete(bizSeq, ts)
				continue
			}
			if _, err := rc.WriteToIP(data, &net.IPAddr{IP: p.dstIP}); err != nil {
				p.stat.Delete(bizSeq, ts)
			}
		}
	}
}

func (a *Agent) closeReadConns() {
	for _, c := range a.rconns {
		_ = c.Close()
	}
}

func (a *Agent) serveRead() error {
	conn, err := a.listenPacket("ip4:udp", a.conf.ClientAddr)
	if err != nil {
		return err
	}
	a.rconns = append(a.rconns, conn)
	setupRawConn(conn, a.conf.TOS, innerPortBPF(int(a.conf.InnerDstPort), a.conf.TOS))
	go a.readLoop(conn)
	return nil
}

func (a *Agent) readLoop(conn net.PacketConn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 2048)
	errCount := 0
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			errCount++
			if errCount >= 20 {
				a.logger.Printf("[ERRO] readLoop exiting after 20 consecutive errors")
				return
			}
			continue
		}
		errCount = 0
		a.handlePacket(buf[:n])
	}
}

// handlePacket parses a returned UDP datagram. With "ip4:udp" the kernel
// strips the IP header, so buf begins with the UDP header (8 bytes)
// followed by the application payload.
func (a *Agent) handlePacket(pkt []byte) {
	if len(pkt) < 8 {
		return
	}
	payload := pkt[8:]
	if !codec.IsValid(payload) {
		return
	}
	seq, ts, srcIP := codec.DecodeWithSrcIP(payload)
	p := a.peerByEVRSrc[srcIP.String()]
	if p == nil {
		return
	}

	if len(payload) == p.msgLen {
		salt := a.salts.Get(seq)
		if !bytes.Equal(salt, payload[codec.MsgHeaderLen:]) {
			a.logger.Printf("[WARN] [client bitflip] %s -> %s, seq=%d, ts=%d",
				p.srcIP, p.dstIP, seq, ts)
			p.stat.Received(seq, ts, time.Now().UnixNano()-ts, true)
			return
		}
	}
	p.stat.Received(seq, ts, time.Now().UnixNano()-ts, false)
}

// innerPortBPF returns a classic BPF program that matches UDP packets
// whose destination port equals innerPort and whose IPv4 TOS equals tos.
// It mirrors the filter used by the original baize/evr agent.
func innerPortBPF(innerPort, tos int) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadIndirect{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 5},
		bpf.LoadIndirect{Off: 1, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(tos), SkipFalse: 3},
		bpf.LoadAbsolute{Off: 22, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(innerPort), SkipFalse: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0x0},
	}
}

func emptyBPF() []bpf.Instruction {
	return []bpf.Instruction{bpf.RetConstant{Val: 0x0}}
}
