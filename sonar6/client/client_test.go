package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baidu/nettools/sonar6/codec"
	"github.com/baidu/nettools/sonar6/config"
	"github.com/baidu/nettools/stat"
	"go.uber.org/ratelimit"

	"golang.org/x/net/bpf"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testConfig() *config.Config {
	return &config.Config{
		Role:            config.RoleClient,
		ClientAddr:      "::1",
		ServerAddrs:     []string{"::1"},
		TOS:             0,
		ClientPortRange: config.PortRange{Min: 43500, Max: 43509},
		ServerPortRange: config.PortRange{Min: 43500, Max: 43504},
		RateInSpan:      100,
		Span:            time.Second,
		Delay:           100 * time.Millisecond,
		MsgLen:          64,
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	conf := testConfig()
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	return NewClient(conf, limiter, sp, nil, logger)
}

// ---------------------------------------------------------------------------
// BPF filter tests (existing)
// ---------------------------------------------------------------------------

func TestEmptyBPF(t *testing.T) {
	prog := emptyBPF()
	if len(prog) != 1 {
		t.Fatalf("expected 1 BPF instruction, got %d", len(prog))
	}
	ret, ok := prog[0].(bpf.RetConstant)
	if !ok {
		t.Fatalf("expected RetConstant, got %T", prog[0])
	}
	if ret.Val != 0x0 {
		t.Errorf("expected RetConstant Val=0x0, got 0x%x", ret.Val)
	}
}

func TestPortRangeBPFInstructionCount(t *testing.T) {
	prog := portRangeBPF(43500, 43599)
	const expected = 5
	if len(prog) != expected {
		t.Errorf("expected %d BPF instructions, got %d", expected, len(prog))
	}
}

func TestPortRangeBPFDstPortOffset(t *testing.T) {
	prog := portRangeBPF(43500, 43599)

	load, ok := prog[0].(bpf.LoadAbsolute)
	if !ok {
		t.Fatalf("expected LoadAbsolute at index 0, got %T", prog[0])
	}
	if load.Off != 2 {
		t.Errorf("expected offset 2 for destination port, got %d", load.Off)
	}
	if load.Size != 2 {
		t.Errorf("expected size 2 for destination port, got %d", load.Size)
	}
}

func TestPortRangeBPFPortRangeChecks(t *testing.T) {
	prog := portRangeBPF(43500, 43599)

	jmpMin, ok := prog[1].(bpf.JumpIf)
	if !ok {
		t.Fatalf("expected JumpIf at index 1, got %T", prog[1])
	}
	if jmpMin.Cond != bpf.JumpGreaterOrEqual {
		t.Errorf("expected JumpGreaterOrEqual for minPort, got %v", jmpMin.Cond)
	}
	if jmpMin.Val != 43500 {
		t.Errorf("expected minPort=43500, got %d", jmpMin.Val)
	}

	jmpMax, ok := prog[2].(bpf.JumpIf)
	if !ok {
		t.Fatalf("expected JumpIf at index 2, got %T", prog[2])
	}
	if jmpMax.Cond != bpf.JumpLessOrEqual {
		t.Errorf("expected JumpLessOrEqual for maxPort, got %v", jmpMax.Cond)
	}
	if jmpMax.Val != 43599 {
		t.Errorf("expected maxPort=43599, got %d", jmpMax.Val)
	}
}

func TestPortRangeBPFReturnValues(t *testing.T) {
	prog := portRangeBPF(43500, 43599)

	accept, ok := prog[3].(bpf.RetConstant)
	if !ok {
		t.Fatalf("expected RetConstant at index 3, got %T", prog[3])
	}
	if accept.Val != 0xffff {
		t.Errorf("expected accept Val=0xffff, got 0x%x", accept.Val)
	}

	reject, ok := prog[4].(bpf.RetConstant)
	if !ok {
		t.Fatalf("expected RetConstant at index 4, got %T", prog[4])
	}
	if reject.Val != 0x0 {
		t.Errorf("expected reject Val=0x0, got 0x%x", reject.Val)
	}
}

func TestPortRangeBPFJumpTargets(t *testing.T) {
	prog := portRangeBPF(43500, 43599)
	rejectIdx := len(prog) - 1

	for i, inst := range prog {
		j, ok := inst.(bpf.JumpIf)
		if !ok {
			continue
		}
		falseTarget := i + 1 + int(j.SkipFalse)
		if falseTarget != rejectIdx {
			t.Errorf("JumpIf at index %d: SkipFalse=%d targets index %d, want REJECT at index %d",
				i, j.SkipFalse, falseTarget, rejectIdx)
		}
	}
}

func TestPortRangeBPFAssemble(t *testing.T) {
	prog := portRangeBPF(43500, 43599)
	assembled, err := bpf.Assemble(prog)
	if err != nil {
		t.Fatalf("failed to assemble BPF program: %v", err)
	}
	if len(assembled) != 5 {
		t.Errorf("expected 5 assembled instructions, got %d", len(assembled))
	}
}

// ---------------------------------------------------------------------------
// packPorts / unpackPorts
// ---------------------------------------------------------------------------

func TestPackUnpackPorts(t *testing.T) {
	tests := []struct {
		local  uint16
		server uint16
	}{
		{0, 0},
		{1, 2},
		{43500, 43509},
		{65535, 65535},
		{12345, 54321},
	}
	for _, tt := range tests {
		packed := packPorts(tt.local, tt.server)
		gotLocal, gotServer := unpackPorts(packed)
		if gotLocal != tt.local || gotServer != tt.server {
			t.Errorf("packPorts(%d,%d) = %d; unpackPorts(%d) = (%d,%d)",
				tt.local, tt.server, packed, packed, gotLocal, gotServer)
		}
	}
}

func TestPackPortsNoOverlap(t *testing.T) {
	seen := make(map[uint32][2]uint16)
	for local := uint16(0); local < 300; local += 37 {
		for server := uint16(0); server < 300; server += 41 {
			packed := packPorts(local, server)
			pair := [2]uint16{local, server}
			if prev, ok := seen[packed]; ok && prev != pair {
				t.Errorf("collision: packPorts(%d,%d) = packPorts(%d,%d) = %d",
					prev[0], prev[1], local, server, packed)
			}
			seen[packed] = pair
		}
	}
}

// ---------------------------------------------------------------------------
// NewClient
// ---------------------------------------------------------------------------

func TestNewClient(t *testing.T) {
	c := testClient(t)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if len(c.peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(c.peers))
	}
	if len(c.salts) != 4 {
		t.Errorf("expected 4 salts, got %d", len(c.salts))
	}

	saltLen := c.conf.MsgLen - codec.MsgHeaderLen
	for i, salt := range c.salts {
		if len(salt) != saltLen {
			t.Errorf("salt[%d] len = %d, want %d", i, len(salt), saltLen)
		}
	}

	if c.ExitOnReachLimit != true {
		t.Error("ExitOnReachLimit should default to true")
	}
	if c.delayBitflip != 30*time.Second {
		t.Errorf("delayBitflip = %v, want %v", c.delayBitflip, 30*time.Second)
	}
	if c.listenPacket == nil {
		t.Error("listenPacket should be set")
	}
}

func TestNewClientMinimumMsgLen(t *testing.T) {
	conf := testConfig()
	conf.MsgLen = 10
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	if c.conf.MsgLen != codec.MsgHeaderLen {
		t.Errorf("MsgLen = %d, want %d", c.conf.MsgLen, codec.MsgHeaderLen)
	}
}

func TestNewClientSaltPatterns(t *testing.T) {
	conf := testConfig()
	conf.MsgLen = 128
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	saltLen := 128 - codec.MsgHeaderLen

	for _, b := range c.salts[0] {
		if b != 0xFF {
			t.Error("salt[0] should be all 0xFF")
			break
		}
	}
	for _, b := range c.salts[1] {
		if b != 0x00 {
			t.Error("salt[1] should be all 0x00")
			break
		}
	}
	for _, b := range c.salts[2] {
		if b != 0x5A {
			t.Error("salt[2] should be all 0x5A")
			break
		}
	}
	expected := codec.ComplementaryBytes(saltLen)
	if !bytes.Equal(c.salts[3], expected) {
		t.Error("salt[3] should match codec.ComplementaryBytes")
	}
}

func TestNewClientMultiplePeers(t *testing.T) {
	conf := testConfig()
	conf.ServerAddrs = []string{"fd00::1", "fd00::2", "fd00::3"}
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	if len(c.peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(c.peers))
	}
	// Keys are canonicalized by net.ParseIP(addr).String()
	for _, addr := range conf.ServerAddrs {
		canonicalKey := net.ParseIP(addr).String()
		if c.peers[canonicalKey] == nil {
			t.Errorf("missing peer for %s (canonical key %s)", addr, canonicalKey)
		}
	}
}

// ---------------------------------------------------------------------------
// initPeers
// ---------------------------------------------------------------------------

func TestInitPeersInitialPorts(t *testing.T) {
	c := testClient(t)
	p := c.peers["::1"]
	if p == nil {
		t.Fatal("expected peer for ::1")
	}

	localPort, serverPort := unpackPorts(p.ports.Load())
	if localPort != uint16(c.conf.ClientPortRange.Min) {
		t.Errorf("localPort = %d, want %d", localPort, c.conf.ClientPortRange.Min)
	}
	if serverPort != uint16(c.conf.ServerPortRange.Min) {
		t.Errorf("serverPort = %d, want %d", serverPort, c.conf.ServerPortRange.Min)
	}
}

func TestInitPeersIPv6Addresses(t *testing.T) {
	conf := testConfig()
	conf.ServerAddrs = []string{"fd00::1"}
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	// Key is canonicalized: net.ParseIP("fd00::1").String() = "fd00::1"
	p := c.peers["fd00::1"]
	if p == nil {
		t.Fatal("expected peer for fd00::1")
	}
	if p.localIP == nil || p.localIP.To16() == nil {
		t.Error("localIP should be a valid IPv6 address")
	}
	if p.serverIP == nil || p.serverIP.To16() == nil {
		t.Error("serverIP should be a valid IPv6 address")
	}
	// net.ParseIP returns 16-byte form for IPv6
	if len(p.localIP) != net.IPv6len {
		t.Errorf("localIP len = %d, want %d", len(p.localIP), net.IPv6len)
	}
	if len(p.serverIP) != net.IPv6len {
		t.Errorf("serverIP len = %d, want %d", len(p.serverIP), net.IPv6len)
	}
}

func TestInitPeersSeqNonZero(t *testing.T) {
	c := testClient(t)
	p := c.peers["::1"]
	if p == nil {
		t.Fatal("expected peer for ::1")
	}
	if p.seq == nil {
		t.Fatal("seq should be non-nil")
	}
	// Just verify it was initialized; value is random
	_ = atomic.LoadUint64(p.seq)
}

func TestInitPeersStatRegistered(t *testing.T) {
	conf := testConfig()
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	p := c.peers["::1"]
	if p == nil {
		t.Fatal("expected peer for ::1")
	}
	if p.stat == nil {
		t.Error("peer stat should be set after initPeers")
	}
}

func TestInitPeersCanonicalKey(t *testing.T) {
	// Verify that extended-form IPv6 addresses are canonicalized as peer keys
	conf := testConfig()
	conf.ServerAddrs = []string{"fd00:0:0:0:0:0:0:1"}
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	// The extended form should NOT be the key
	if c.peers["fd00:0:0:0:0:0:0:1"] != nil {
		t.Error("extended form should not be used as peer key")
	}
	// The canonical form should be the key
	p := c.peers["fd00::1"]
	if p == nil {
		t.Fatal("expected peer for canonical key fd00::1")
	}
	if !p.serverIP.Equal(net.ParseIP("fd00::1")) {
		t.Errorf("serverIP = %v, want fd00::1", p.serverIP)
	}
}

// ---------------------------------------------------------------------------
// setupRawConn
// ---------------------------------------------------------------------------

func TestSetupRawConnWithUDPConn(t *testing.T) {
	// setupRawConn should silently skip non-IPConn connections (test sockets)
	conn, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot create UDP socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Should not panic or error when given a UDPConn
	setupRawConn(conn, 128, nil)
}

// ---------------------------------------------------------------------------
// Test helpers for T-002 methods
// ---------------------------------------------------------------------------

// makeTestUDPPacket constructs a raw UDP datagram (header + payload) suitable
// for handlePacket, which expects data as delivered by AF_INET6 SOCK_RAW
// (starting at the UDP header, no IPv6 header).
func makeTestUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpData, err := codec.EncodeUDPPacket(srcIP.To16(), dstIP.To16(), srcPort, dstPort, 0, 64, payload)
	if err != nil {
		panic(err)
	}
	return udpData
}

// mockPacketConn implements net.PacketConn for testing readLoop.
type mockPacketConn struct {
	mu      sync.Mutex
	packets []struct {
		data []byte
		addr net.Addr
	}
	idx    int
	closed bool
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, nil, net.ErrClosed
	}
	if m.idx >= len(m.packets) {
		return 0, nil, io.EOF
	}
	pkt := m.packets[m.idx]
	copy(p, pkt.data)
	m.idx++
	return len(pkt.data), pkt.addr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return len(p), nil
}
func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}
func (m *mockPacketConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.ParseIP("::1")} }
func (m *mockPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// trackingStat wraps a real stat.Stat and records Received calls.
type trackingStat struct {
	stat.Stat
	receivedCount atomic.Int64
	lastReceived  struct {
		mu         sync.Mutex
		seq        uint64
		hasBitflip bool
	}
}

func (t *trackingStat) Received(seq uint64, ts, rtt int64, hasBitflip bool) {
	t.receivedCount.Add(1)
	t.lastReceived.mu.Lock()
	t.lastReceived.seq = seq
	t.lastReceived.hasBitflip = hasBitflip
	t.lastReceived.mu.Unlock()
	t.Stat.Received(seq, ts, rtt, hasBitflip)
}

// ---------------------------------------------------------------------------
// reachedLimit
// ---------------------------------------------------------------------------

func TestReachedLimitContextCancel(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- c.reachedLimit(ctx)
	}()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reachedLimit should return quickly on context cancel")
	}
}

func TestReachedLimitExitOnReachLimitFalse(t *testing.T) {
	c := testClient(t)
	c.ExitOnReachLimit = false
	c.conf.Delay = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.reachedLimit(ctx)
	}()

	// Cancel to avoid waiting the full delay+10s
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reachedLimit should return on cancel")
	}
}

// ---------------------------------------------------------------------------
// closeReadConns
// ---------------------------------------------------------------------------

func TestCloseReadConns(t *testing.T) {
	c := testClient(t)

	conn1, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot create UDP socket: %v", err)
	}
	conn2, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot create UDP socket: %v", err)
	}

	c.rconns = []net.PacketConn{conn1, conn2}
	c.closeReadConns()
	// Should not panic; conns are now closed
}

func TestCloseReadConnsEmpty(t *testing.T) {
	c := testClient(t)
	c.rconns = nil
	c.closeReadConns() // should not panic
}

// ---------------------------------------------------------------------------
// handlePacket
// ---------------------------------------------------------------------------

func TestHandlePacketValidPayload(t *testing.T) {
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("::1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 1 {
		t.Errorf("expected 1 Received call, got %d", tstat.receivedCount.Load())
	}
}

func TestHandlePacketInvalidMagic(t *testing.T) {
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	payload := make([]byte, 64)
	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("::1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 0 {
		t.Error("stat.Received should NOT be called for invalid magic")
	}
}

func TestHandlePacketNoPeer(t *testing.T) {
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("fd00::99")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 0 {
		t.Error("stat.Received should NOT be called for unknown peer")
	}
}

func TestHandlePacketLinkLocalWithZone(t *testing.T) {
	// Verify that peer lookup works when remote includes a zone suffix
	// (e.g. "fe80::1%eth0") but peers map key is the canonical form
	// without zone ("fe80::1").
	conf := &config.Config{
		Role:            config.RoleClient,
		ClientAddr:      "fe80::1",
		ServerAddrs:     []string{"fe80::1"},
		TOS:             0,
		ClientPortRange: config.PortRange{Min: 43500, Max: 43509},
		ServerPortRange: config.PortRange{Min: 43500, Max: 43504},
		RateInSpan:      100,
		Span:            time.Second,
		Delay:           100 * time.Millisecond,
		MsgLen:          64,
	}
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	p := c.peers["fe80::1"]
	if p == nil {
		t.Fatal("expected peer for fe80::1")
	}
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	pkt := makeTestUDPPacket(net.ParseIP("fe80::1"), net.ParseIP("fe80::1"), 43500, 43500, payload)
	// Remote with zone suffix — this is what raw IPv6 sockets return for link-local
	remote := &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 1 {
		t.Errorf("expected 1 Received call with zone in remote, got %d", tstat.receivedCount.Load())
	}
}

func TestHandlePacketShortPayload(t *testing.T) {
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	seq := uint64(2)
	ts := time.Now().UnixNano()
	payload := codec.Encode(seq, nil, ts, codec.MsgHeaderLen, 50, 0, 0)

	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("::1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 1 {
		t.Errorf("expected 1 Received call for short payload, got %d", tstat.receivedCount.Load())
	}
}

func TestHandlePacketNoUDPLayer(t *testing.T) {
	c := testClient(t)

	// Send raw garbage that goscapy can't parse
	remote := &net.IPAddr{IP: net.ParseIP("::1")}
	c.handlePacket(remote, []byte{0x01, 0x02, 0x03})
}

func TestHandlePacketBitflipEarlyReturn(t *testing.T) {
	// When bitflip is detected (not suppressed), handlePacket should return
	// early without calling stat.Received.
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	// Activate bitflip detection
	origStartup := startupTime
	startupTime = time.Now().Add(-60 * time.Second)
	defer func() { startupTime = origStartup }()

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	// Corrupt the salt region
	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[codec.MsgHeaderLen+2] ^= 0xFF

	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, corrupted)
	remote := &net.IPAddr{IP: net.ParseIP("::1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 0 {
		t.Error("stat.Received should NOT be called when bitflip is detected (early return)")
	}
}

func TestHandlePacketBitflipSuppressedStillRecords(t *testing.T) {
	// When bitflip is suppressed (startup period), detectBitflip returns false,
	// so handlePacket falls through to stat.Received with hasBitflip=false.
	c := testClient(t)

	p := c.peers["::1"]
	tstat := &trackingStat{Stat: p.stat}
	p.stat = tstat

	// Suppress bitflip detection (startup period)
	origStartup := startupTime
	startupTime = time.Now()
	defer func() { startupTime = origStartup }()

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	// Corrupt the salt
	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[codec.MsgHeaderLen+2] ^= 0xFF

	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, corrupted)
	remote := &net.IPAddr{IP: net.ParseIP("::1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 1 {
		t.Error("stat.Received should be called when bitflip is suppressed (no early return)")
	}
	tstat.lastReceived.mu.Lock()
	hb := tstat.lastReceived.hasBitflip
	tstat.lastReceived.mu.Unlock()
	if hb {
		t.Error("hasBitflip should be false when bitflip detection is suppressed")
	}
}

// ---------------------------------------------------------------------------
// detectBitflip
// ---------------------------------------------------------------------------

func TestDetectBitflipActive(t *testing.T) {
	c := testClient(t)

	origStartup := startupTime
	startupTime = time.Now().Add(-60 * time.Second)
	defer func() { startupTime = origStartup }()

	p := c.peers["::1"]
	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[codec.MsgHeaderLen+2] ^= 0x01

	if !c.detectBitflip(p, corrupted, salt, seq, ts) {
		t.Error("expected bitflip detection for corrupted payload")
	}
}

func TestDetectBitflipSuppressed(t *testing.T) {
	c := testClient(t)

	origStartup := startupTime
	startupTime = time.Now()
	defer func() { startupTime = origStartup }()

	p := c.peers["::1"]
	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[codec.MsgHeaderLen+2] ^= 0x01

	if c.detectBitflip(p, corrupted, salt, seq, ts) {
		t.Error("expected bitflip detection to be suppressed during startup period")
	}
}

// ---------------------------------------------------------------------------
// readLoop
// ---------------------------------------------------------------------------

func TestReadLoopNormalRead(t *testing.T) {
	c := testClient(t)

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)
	pkt := makeTestUDPPacket(net.ParseIP("::1"), net.ParseIP("::1"), 43500, 43500, payload)

	mc := &mockPacketConn{
		packets: []struct {
			data []byte
			addr net.Addr
		}{
			{data: pkt, addr: &net.IPAddr{IP: net.ParseIP("::1")}},
		},
	}

	done := make(chan struct{})
	go func() {
		c.readLoop(mc)
		close(done)
	}()

	// readLoop will read 1 packet, then hit EOF errors.
	// After 10 consecutive errors it exits.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop should exit after 10 consecutive errors")
	}
}

func TestReadLoopErrorCounting(t *testing.T) {
	c := testClient(t)

	// No packets → every ReadFrom returns error → exits after 10
	mc := &mockPacketConn{}

	done := make(chan struct{})
	go func() {
		c.readLoop(mc)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop should exit after 10 consecutive errors")
	}
}

func TestReadLoopClosedConn(t *testing.T) {
	c := testClient(t)

	mc := &mockPacketConn{}
	_ = mc.Close()

	done := make(chan struct{})
	go func() {
		c.readLoop(mc)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop should exit quickly on closed conn")
	}
}

// ---------------------------------------------------------------------------
// serveWrite with injectable dialer
// ---------------------------------------------------------------------------

func TestServeWriteCountLimit(_ *testing.T) {
	conf := testConfig()
	conf.Count = 3 // stop after 3 packets
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	}

	// Cancel context shortly after limit is reached (reachedLimit waits Delay+10s)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	err := c.serveWrite(ctx)
	_ = err // may be nil or canceled, either is fine
}

func TestServeWriteSendDurationLimit(_ *testing.T) {
	conf := testConfig()
	conf.SendDuration = 50 * time.Millisecond
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	}

	// Cancel context shortly after limit is reached
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	_ = c.serveWrite(ctx) // may return nil or context error
}

func TestServeWriteContextCancel(t *testing.T) {
	conf := testConfig()
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.serveWrite(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveWrite should return on context cancel")
	}
}

func TestServeWriteDialerError(t *testing.T) {
	c := testClient(t)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return nil, net.ErrClosed
	}

	ctx := context.Background()
	err := c.serveWrite(ctx)
	if err == nil {
		t.Error("expected error from failed dialer")
	}
}

// ---------------------------------------------------------------------------
// serveRead with injectable dialer
// ---------------------------------------------------------------------------

func TestServeReadWithUDPConn(t *testing.T) {
	conf := testConfig()
	conf.ClientPortRange = config.PortRange{Min: 43500, Max: 43500}

	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	}

	err := c.serveRead()
	if err != nil {
		t.Fatalf("serveRead with UDP dialer: %v", err)
	}
	if len(c.rconns) != 1 {
		t.Errorf("expected 1 read conn, got %d", len(c.rconns))
	}

	c.closeReadConns()
}

func TestServeReadDialerError(t *testing.T) {
	c := testClient(t)
	c.conf.ClientPortRange = config.PortRange{Min: 43500, Max: 43500}

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return nil, net.ErrClosed
	}

	err := c.serveRead()
	if err == nil {
		t.Error("expected error from failed dialer")
	}
}

func TestServeReadGoroutineCount(t *testing.T) {
	// Verify that the port range is split across the expected number of goroutines
	tests := []struct {
		name      string
		portRange config.PortRange
		wantConns int
	}{
		{"single port", config.PortRange{Min: 43500, Max: 43500}, 1},
		{"4 ports", config.PortRange{Min: 43500, Max: 43503}, 4},
		{"8 ports", config.PortRange{Min: 43500, Max: 43507}, 8},
		{"16 ports", config.PortRange{Min: 43500, Max: 43515}, 8}, // capped at 8
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := testConfig()
			conf.ClientPortRange = tt.portRange

			limiter := ratelimit.New(100)
			sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
			logger := log.New(io.Discard, "", 0)
			c := NewClient(conf, limiter, sp, nil, logger)

			c.listenPacket = func(_, _ string) (net.PacketConn, error) {
				return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
			}

			err := c.serveRead()
			if err != nil {
				t.Fatalf("serveRead: %v", err)
			}

			if len(c.rconns) != tt.wantConns {
				t.Errorf("expected %d read conns, got %d", tt.wantConns, len(c.rconns))
			}

			c.closeReadConns()
		})
	}
}

// ---------------------------------------------------------------------------
// Run (integration)
// ---------------------------------------------------------------------------

func TestRunContextCancel(t *testing.T) {
	conf := testConfig()
	conf.ClientPortRange = config.PortRange{Min: 43500, Max: 43500}
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("::1")})
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Run(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-errCh:
		// ok — Run returned on cancel
	case <-time.After(10 * time.Second):
		t.Fatal("Run should return on context cancel")
	}
}
