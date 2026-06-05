// Package client implements the IPv6 UDP probe client for the bitflip
// detection tool. It provides BPF filter construction for IPv6 packets
// with correct header offsets for next-header, traffic class, and
// destination port fields, along with the Client struct and peer
// management for sending probes and detecting bit-flip corruption.
package client

import (
	"bytes"
	"context"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/smallnest/goscapy/pkg/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"

	sonarconfig "github.com/baidu/nettools/sonar/config"
	"github.com/baidu/nettools/sonar6/codec"
	"github.com/baidu/nettools/sonar6/config"
	"github.com/baidu/nettools/stat"

	"go.uber.org/ratelimit"
)

// peer holds per-server state: address, sequence counter, IP pair,
// port ranges, and the associated Stat instance for tracking probes.
type peer struct {
	serverAddr      string
	stat            stat.Stat
	seq             *uint64
	localIP         net.IP
	serverIP        net.IP
	serverZone      string
	msgLen          int
	clientPortRange config.PortRange
	serverPortRange config.PortRange
	// ports packs localPort (high 16 bits) and serverPort (low 16 bits)
	// into a single atomic value to avoid data races between the write
	// and read goroutines.
	ports atomic.Uint32
}

// Client sends IPv6 UDP probe packets to server peers, listens for echoes,
// and detects packet loss and bit-flip corruption in returned payloads.
type Client struct {
	conf          *config.Config
	limiter       ratelimit.Limiter
	statProcessor *stat.Processor
	logger        *log.Logger
	sender        stat.Sender

	peers map[string]*peer

	salts map[int][]byte

	// ExitOnReachLimit controls whether the client returns when the
	// configured packet count or send duration limit is reached.
	ExitOnReachLimit bool
	delayBitflip     time.Duration

	rconns []net.PacketConn

	// listenPacket creates a PacketConn. Defaults to net.ListenPacket;
	// overridden in tests to use UDP sockets instead of raw IP.
	listenPacket func(network, address string) (net.PacketConn, error)
}

// NewClient creates a Client with the given configuration, rate limiter,
// statistics processor, and logger. It initializes four salt patterns
// (0xFF, 0x00, 0x5A, deterministic random) for bit-flip detection.
// If sender is nil, a LogSender with the provided logger is used.
func NewClient(conf *config.Config, limiter ratelimit.Limiter,
	statProcessor *stat.Processor, sender stat.Sender, logger *log.Logger,
) *Client {
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}

	if sender == nil {
		sender = stat.NewLogSender(logger, conf.Verbose)
	}

	c := &Client{
		conf:             conf,
		limiter:          limiter,
		logger:           logger,
		sender:           sender,
		statProcessor:    statProcessor,
		peers:            make(map[string]*peer),
		ExitOnReachLimit: true,
		delayBitflip:     30 * time.Second,
		listenPacket:     net.ListenPacket,
	}

	c.salts = map[int][]byte{
		0: bytes.Repeat([]byte{0xFF}, conf.MsgLen-codec.MsgHeaderLen),
		1: bytes.Repeat([]byte{0x00}, conf.MsgLen-codec.MsgHeaderLen),
		2: bytes.Repeat([]byte{0x5A}, conf.MsgLen-codec.MsgHeaderLen),
		3: codec.ComplementaryBytes(conf.MsgLen - codec.MsgHeaderLen),
	}

	c.initPeers()

	return c
}

// packPorts packs two uint16 port numbers into a uint32 for atomic storage.
func packPorts(local, server uint16) uint32 {
	return uint32(local)<<16 | uint32(server)
}

// unpackPorts extracts local and server port from a packed uint32.
func unpackPorts(v uint32) (local, server uint16) {
	return uint16(v >> 16), uint16(v)
}

// initPeers creates a peer entry for each configured server address,
// assigns a random initial sequence number, and registers a Stat instance.
// Peer map keys are canonicalized via net.ParseIP(addr).String() so that
// IPv6 address lookups work regardless of the textual format used in config
// (e.g. "fd00:0:0:0:0:0:0:1" and "fd00::1" both resolve to "fd00::1").
func (c *Client) initPeers() {
	for _, addr := range c.conf.ServerAddrs {
		canonicalKey := net.ParseIP(addr).String()
		seq := uint64(rand.Int63())
		p := &peer{
			serverAddr:      addr,
			seq:             &seq,
			localIP:         net.ParseIP(c.conf.ClientAddr),
			serverIP:        net.ParseIP(addr),
			serverZone:      c.conf.ServerZone,
			msgLen:          c.conf.MsgLen,
			clientPortRange: c.conf.ClientPortRange,
			serverPortRange: c.conf.ServerPortRange,
		}
		p.ports.Store(packPorts(uint16(c.conf.ClientPortRange.Min), uint16(c.conf.ServerPortRange.Min)))
		c.peers[canonicalKey] = p
		c.logger.Printf("[INFO] configured peer %s, seq %d", addr, seq)

		s := stat.NewStat(c.conf.ClientAddr, addr,
			sonarconfig.PortRange{Min: c.conf.ClientPortRange.Min, Max: c.conf.ClientPortRange.Max},
			sonarconfig.PortRange{Min: c.conf.ServerPortRange.Min, Max: c.conf.ServerPortRange.Max},
			c.conf.RateInSpan, c.conf.Span, c.conf.Delay, c.sender)
		c.statProcessor.AddStat(s)
		p.stat = s
	}
}

// localAddr returns the client address with zone appended for link-local
// IPv6 addresses.
func (c *Client) localAddr() string {
	if c.conf.ClientZone != "" {
		return c.conf.ClientAddr + "%" + c.conf.ClientZone
	}
	return c.conf.ClientAddr
}

// setupRawConn configures buffer sizes, BPF filter, and traffic class on a
// raw IPv6 connection. If the connection is not a *net.IPConn (e.g. a test
// UDP socket), the setup is skipped.
func setupRawConn(conn net.PacketConn, trafficClass int, bpfInst []bpf.Instruction) {
	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		return
	}
	_ = ipConn.SetReadBuffer(20 * 1024 * 1024)
	_ = ipConn.SetWriteBuffer(20 * 1024 * 1024)

	pconn := ipv6.NewPacketConn(conn)
	if len(bpfInst) > 0 {
		if assembled, err := bpf.Assemble(bpfInst); err == nil {
			_ = pconn.SetBPF(assembled)
		}
	}
	_ = pconn.SetTrafficClass(trafficClass)
}

// portRangeBPF returns a classic BPF program that filters for UDP packets
// with destination port within [minPort, maxPort].
//
// On AF_INET6 SOCK_RAW sockets, the kernel strips the IPv6 fixed header
// before delivering data to BPF. The filter sees data starting at the
// UDP header:
//   - Offset 0: source port (2 bytes)
//   - Offset 2: destination port (2 bytes)
//   - Offset 4: length (2 bytes)
//   - Offset 6: checksum (2 bytes)
func portRangeBPF(minPort, maxPort int) []bpf.Instruction {
	return []bpf.Instruction{
		// Load destination port at offset 2
		bpf.LoadAbsolute{Off: 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: uint32(minPort), SkipFalse: 2},
		bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: uint32(maxPort), SkipFalse: 1},

		// Accept
		bpf.RetConstant{Val: 0xffff},
		// Reject
		bpf.RetConstant{Val: 0x0},
	}
}

// emptyBPF returns a BPF program that drops all packets.
func emptyBPF() []bpf.Instruction {
	return []bpf.Instruction{bpf.RetConstant{Val: 0x0}}
}

// Run starts the client by launching read goroutines and then entering
// the send loop. It blocks until the context is cancelled or a limit is reached.
func (c *Client) Run(ctx context.Context) error {
	if err := c.serveRead(); err != nil {
		return err
	}
	time.Sleep(3 * time.Second)
	return c.serveWrite(ctx)
}

// serveWrite is the main send loop. It opens a raw IPv6 socket, encodes
// probe packets with rotating salts and ports, and sends them to all
// peers at the configured rate. It tracks time-bucketed sent counts
// for loss-rate calculation.
func (c *Client) serveWrite(ctx context.Context) error {
	conn, err := c.listenPacket("ip6:udp", c.localAddr())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	defer c.closeReadConns()

	setupRawConn(conn, c.conf.TOS, emptyBPF())

	span := int64(c.conf.Span)
	c.logger.Printf("[INFO] client TOS: %d, span: %v, zone: client=%s server=%s", c.conf.TOS, c.conf.Span, c.conf.ClientZone, c.conf.ServerZone)

	bucketIDs := make(map[*peer]int64)
	lastSent := make(map[*peer]uint32)
	curSent := make(map[*peer]uint32)
	lastStartSrcPort := make(map[*peer]uint16)
	lastStartDstPort := make(map[*peer]uint16)
	curStartSrcPort := make(map[*peer]uint16)
	curStartDstPort := make(map[*peer]uint16)
	for _, p := range c.peers {
		curSent[p] = uint32(c.conf.RateInSpan)
		curStartSrcPort[p] = uint16(c.conf.ClientPortRange.Min)
		curStartDstPort[p] = uint16(c.conf.ServerPortRange.Min)
	}

	count := 0
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.limiter.Take()

		for _, p := range c.peers {
			bizSeq := atomic.AddUint64(p.seq, 1)
			localPort, serverPort := unpackPorts(p.ports.Load())
			localPort, serverPort = config.GetNextPorts(localPort, serverPort, p.clientPortRange, p.serverPortRange)
			p.ports.Store(packPorts(localPort, serverPort))

			ts := time.Now().UnixNano()
			bucketID := ts / span
			if bucketID != bucketIDs[p] {
				bucketIDs[p] = bucketID
				lastSent[p] = curSent[p]
				lastStartSrcPort[p] = curStartSrcPort[p]
				lastStartDstPort[p] = curStartDstPort[p]
				curSent[p] = 1
				curStartSrcPort[p] = localPort
				curStartDstPort[p] = serverPort
			} else {
				curSent[p]++
			}

			payload := codec.Encode(bizSeq, c.salts[int(bizSeq%4)], ts, p.msgLen, lastSent[p], lastStartSrcPort[p], lastStartDstPort[p])
			data, err := codec.EncodeUDPPacket(p.localIP, p.serverIP, localPort, serverPort, uint8(c.conf.TOS), 64, payload)
			if err != nil {
				continue
			}

			count++
			if c.conf.Count > 0 && count > c.conf.Count {
				return c.reachedLimit(ctx)
			}
			if c.conf.SendDuration > 0 && time.Since(start) > c.conf.SendDuration {
				return c.reachedLimit(ctx)
			}

			p.stat.Put(localPort, serverPort, bizSeq, ts)
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				continue
			}
			if _, err := conn.WriteTo(data, &net.IPAddr{IP: p.serverIP, Zone: p.serverZone}); err != nil {
				p.stat.Delete(bizSeq, ts)
			}
		}
	}
}

// reachedLimit waits for the configured delay (plus a grace period for
// in-flight packets) before returning, giving stats time to collect
// final results.
func (c *Client) reachedLimit(ctx context.Context) error {
	select {
	case <-ctx.Done():
	case <-time.After(c.conf.Delay + 10*time.Second):
	}
	if c.ExitOnReachLimit {
		c.logger.Printf("[INFO] reached limit, exiting")
	} else {
		c.logger.Printf("[INFO] reached limit, returning")
	}
	return nil
}

// closeReadConns closes all read-side packet connections.
func (c *Client) closeReadConns() {
	for _, conn := range c.rconns {
		_ = conn.Close()
	}
}

// serveRead opens multiple raw IPv6 sockets for receiving echoed packets.
// The client port range is split across up to 8 goroutines, each with
// a BPF filter that matches only the assigned sub-range and traffic class.
func (c *Client) serveRead() error {
	pr := c.conf.ClientPortRange
	portCount := pr.Max - pr.Min + 1
	gcount := min(portCount, 8)
	portsPerG := (portCount + gcount - 1) / gcount

	for i := pr.Min; i <= pr.Max; i += portsPerG {
		conn, err := c.listenPacket("ip6:udp", c.localAddr())
		if err != nil {
			return err
		}
		c.rconns = append(c.rconns, conn)

		upper := i + portsPerG - 1
		if upper > pr.Max {
			upper = pr.Max
		}

		setupRawConn(conn, c.conf.TOS, portRangeBPF(i, upper))

		go c.readLoop(conn)
	}
	return nil
}

// readLoop reads packets from a connection and dispatches them to
// handlePacket. It exits after 10 consecutive errors.
func (c *Client) readLoop(conn net.PacketConn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 10240)
	errCount := 0

	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			errCount++
			if errCount >= 10 {
				c.logger.Printf("[ERRO] readLoop exiting after 10 consecutive errors")
				return
			}
			continue
		}
		errCount = 0
		c.handlePacket(remote, buf[:n])
	}
}

var startupTime = time.Now()

// handlePacket parses a received UDP packet, validates it against the
// expected magic flag, and records the probe as received. If the payload
// salt differs from the expected pattern (selected by seq%4), it invokes
// detectBitflip for detailed byte-level logging.
//
// AF_INET6 SOCK_RAW sockets deliver data starting at the UDP header
// (the IPv6 fixed header is stripped by the kernel). We parse directly
// from LayerTypeUDP.
func (c *Client) handlePacket(remote net.Addr, pkt []byte) {
	parsed, err := packet.DissectByProto(pkt, "UDP")
	if err != nil {
		return
	}
	rawLayer := parsed.GetLayer("Raw")
	if rawLayer == nil {
		return
	}
	loadVal, _ := rawLayer.Get("load")
	payload, _ := loadVal.([]byte)
	if len(payload) == 0 {
		return
	}

	if !codec.IsValid(payload) {
		return
	}

	// Canonicalize the remote address by stripping the zone suffix.
	// For link-local IPv6 addresses, remote.String() includes the zone
	// (e.g. "fe80::1%eth0"), but the peers map keys are canonicalized
	// via net.ParseIP(addr).String() which omits the zone.
	// net.ParseIP cannot parse addresses with %zone, so we extract
	// the IP from the Addr type directly when available.
	peerKey := remote.String()
	if ipAddr, ok := remote.(*net.IPAddr); ok && len(ipAddr.IP) > 0 {
		peerKey = ipAddr.IP.String()
	}

	seq, ts, _, _, _ := codec.Decode(payload)
	p := c.peers[peerKey]
	if p == nil {
		return
	}

	hasBitflip := false
	if len(payload) == c.conf.MsgLen {
		salt := c.salts[int(seq%4)]
		if !bytes.Equal(salt, payload[codec.MsgHeaderLen:]) {
			hasBitflip = c.detectBitflip(p, payload, salt, seq, ts)
			if hasBitflip {
				return
			}
		}
	}

	p.stat.Received(seq, ts, time.Now().UnixNano()-ts, hasBitflip)
}

// detectBitflip compares each payload byte against the expected salt and
// logs every mismatch with the five-tuple and byte offset. It returns true
// if any bit-flip is detected. Detection is suppressed during the initial
// delayBitflip period to avoid false positives from startup noise.
func (c *Client) detectBitflip(p *peer, payload, salt []byte, seq uint64, ts int64) bool {
	if time.Since(startupTime) <= c.delayBitflip {
		return false
	}

	for i, v := range payload[codec.MsgHeaderLen:] {
		if v != salt[i] {
			localPort, serverPort := unpackPorts(p.ports.Load())
			c.logger.Printf("[ERRO] [client bitflip] %s:%d -> %s:%d, %02x->%02x, idx: %d, seq: %d, ts: %d",
				p.localIP, localPort, p.serverIP, serverPort, salt[i], v, i+codec.MsgHeaderLen, seq, ts)
		}
	}

	return true
}
