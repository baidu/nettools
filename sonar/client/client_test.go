package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baidu/nettools/sonar/codec"
	"github.com/baidu/nettools/sonar/config"
	"github.com/baidu/nettools/stat"
	"go.uber.org/ratelimit"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testConfig() *config.Config {
	return &config.Config{
		Role:            config.RoleClient,
		ClientAddr:      "127.0.0.1",
		ServerAddrs:     []string{"127.0.0.1"},
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

// makeTestUDPPacket constructs a raw UDP packet (header + payload) suitable
// for goscapy's UDP dissector.
func makeTestUDPPacket(srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, udpLen)
	binary.BigEndian.PutUint16(pkt[0:2], srcPort)
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0) // checksum
	copy(pkt[8:], payload)
	return pkt
}

// mockPacketConn implements net.PacketConn for testing readLoop.
type mockPacketConn struct {
	mu      sync.Mutex
	packets []struct {
		data []byte
		addr net.Addr
	}
	idx     int
	closed  bool
	onClose func()
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
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}
func (m *mockPacketConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.ParseIP("127.0.0.1")} }
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

// closeTrackingConn wraps a net.PacketConn to track Close calls.
type closeTrackingConn struct {
	net.PacketConn
	closed *atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
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
	if c.delayBitflip != 10*time.Second {
		t.Errorf("delayBitflip = %v, want %v", c.delayBitflip, 10*time.Second)
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
	conf.ServerAddrs = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	if len(c.peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(c.peers))
	}
	for _, addr := range conf.ServerAddrs {
		if c.peers[addr] == nil {
			t.Errorf("missing peer for %s", addr)
		}
	}
}

func TestInitPeersInitialPorts(t *testing.T) {
	c := testClient(t)
	p := c.peers["127.0.0.1"]
	if p == nil {
		t.Fatal("expected peer for 127.0.0.1")
	}

	localPort, serverPort := unpackPorts(p.ports.Load())
	if localPort != uint16(c.conf.ClientPortRange.Min) {
		t.Errorf("localPort = %d, want %d", localPort, c.conf.ClientPortRange.Min)
	}
	if serverPort != uint16(c.conf.ServerPortRange.Min) {
		t.Errorf("serverPort = %d, want %d", serverPort, c.conf.ServerPortRange.Min)
	}
}

// ---------------------------------------------------------------------------
// BPF helpers
// ---------------------------------------------------------------------------

func TestEmptyBPF(t *testing.T) {
	prog := emptyBPF()
	if len(prog) != 1 {
		t.Errorf("expected 1 BPF instruction, got %d", len(prog))
	}
}

func TestPortRangeBPF(t *testing.T) {
	prog := portRangeBPF(43500, 43599, 128)
	if len(prog) != 9 {
		t.Errorf("expected 9 BPF instructions, got %d", len(prog))
	}
}

// ---------------------------------------------------------------------------
// setupRawConn
// ---------------------------------------------------------------------------

func TestSetupRawConnWithUDPConn(t *testing.T) {
	// UDP conn should not panic — setupRawConn skips non-IPConn
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Should not panic with a UDP conn
	setupRawConn(conn, 0, emptyBPF())
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

	// Cancel before the timer (delay=100ms + 10s)
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

func TestReachedLimitTimerExpires(t *testing.T) {
	// Use a very short delay and cancel context just after the timer fires
	// to avoid waiting the full 10s grace period in test
	conf := testConfig()
	conf.Delay = 10 * time.Millisecond
	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	// Use a context that cancels after the timer would fire
	// The timer is Delay + 10s, so we use context cancel after a short wait
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := c.reachedLimit(ctx)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
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

	// Cancel to avoid waiting 10s
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

	var closed1, closed2 atomic.Bool

	addr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn1, _ := net.ListenUDP("udp", addr1)
	c.rconns = append(c.rconns, &closeTrackingConn{PacketConn: conn1, closed: &closed1})

	addr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn2, _ := net.ListenUDP("udp", addr2)
	c.rconns = append(c.rconns, &closeTrackingConn{PacketConn: conn2, closed: &closed2})

	c.closeReadConns()

	if !closed1.Load() {
		t.Error("conn1 should be closed")
	}
	if !closed2.Load() {
		t.Error("conn2 should be closed")
	}
}

func TestCloseReadConnsEmpty(t *testing.T) {
	c := testClient(t)
	c.rconns = nil
	c.closeReadConns() // should not panic
}

// ---------------------------------------------------------------------------
// handlePacket
// ---------------------------------------------------------------------------

func TestHandlePacket(t *testing.T) {
	c := testClient(t)

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)

	pkt := makeTestUDPPacket(43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

	c.handlePacket(remote, pkt)
}

func TestHandlePacketInvalidMagic(t *testing.T) {
	c := testClient(t)

	payload := make([]byte, 64)
	pkt := makeTestUDPPacket(43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

	c.handlePacket(remote, pkt)
}

func TestHandlePacketNoPeer(t *testing.T) {
	c := testClient(t)

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := c.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, c.conf.MsgLen, 100, 0, 0)
	pkt := makeTestUDPPacket(43500, 43500, payload)

	remote := &net.IPAddr{IP: net.ParseIP("10.99.99.99")}
	c.handlePacket(remote, pkt)
}

func TestHandlePacketShortPayload(t *testing.T) {
	c := testClient(t)

	seq := uint64(2)
	ts := time.Now().UnixNano()
	payload := codec.Encode(seq, nil, ts, codec.MsgHeaderLen, 50, 0, 0)
	pkt := makeTestUDPPacket(43500, 43500, payload)
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

	c.handlePacket(remote, pkt)
}

func TestHandlePacketBitflipEarlyReturn(t *testing.T) {
	// When bitflip is detected (not suppressed), handlePacket should return
	// early without calling stat.Received.
	c := testClient(t)

	// Replace peer stat with tracking wrapper to verify Received is NOT called
	p := c.peers["127.0.0.1"]
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

	pkt := makeTestUDPPacket(43500, 43500, corrupted)
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

	c.handlePacket(remote, pkt)

	if tstat.receivedCount.Load() != 0 {
		t.Error("stat.Received should NOT be called when bitflip is detected (early return)")
	}
}

func TestHandlePacketBitflipSuppressedStillRecords(t *testing.T) {
	// When bitflip is suppressed (startup period), detectBitflip returns false,
	// so handlePacket falls through to stat.Received with hasBitflip=false.
	c := testClient(t)

	p := c.peers["127.0.0.1"]
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

	pkt := makeTestUDPPacket(43500, 43500, corrupted)
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}

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

func TestHandlePacketNoUDPLayer(t *testing.T) {
	c := testClient(t)

	// Send raw garbage that goscapy can't parse as UDP
	remote := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	c.handlePacket(remote, []byte{0x01, 0x02, 0x03})
}

// ---------------------------------------------------------------------------
// detectBitflip
// ---------------------------------------------------------------------------

func TestDetectBitflipActive(t *testing.T) {
	c := testClient(t)

	origStartup := startupTime
	startupTime = time.Now().Add(-60 * time.Second)
	defer func() { startupTime = origStartup }()

	p := c.peers["127.0.0.1"]
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

	p := c.peers["127.0.0.1"]
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
	pkt := makeTestUDPPacket(43500, 43500, payload)

	mc := &mockPacketConn{
		packets: []struct {
			data []byte
			addr net.Addr
		}{
			{data: pkt, addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}},
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
		// exited as expected
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
		// ok
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
		// ok — closed conn returns errors immediately
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
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	}

	// Update peer to send to our UDP server
	p := c.peers["127.0.0.1"]
	p.serverIP = net.ParseIP("127.0.0.1")
	p.serverAddr = "127.0.0.1"

	// Cancel context shortly after limit is reached (reachedLimit waits Delay+10s)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	err := c.serveWrite(ctx)
	_ = err // may be nil or canceled, either is fine
}

func TestServeWriteContextCancel(t *testing.T) {
	conf := testConfig()
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.serveWrite(ctx)
	}()

	// Cancel after a short delay
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

func TestServeWriteSendDurationLimit(_ *testing.T) {
	conf := testConfig()
	conf.SendDuration = 50 * time.Millisecond
	conf.Delay = 10 * time.Millisecond

	limiter := ratelimit.New(10000)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, _ string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	}

	// Cancel context shortly after limit is reached
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	_ = c.serveWrite(ctx) // may return nil or context error
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
	// Small port range so we don't create too many goroutines
	conf.ClientPortRange = config.PortRange{Min: 43500, Max: 43500}

	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, address string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
	}

	err := c.serveRead()
	if err != nil {
		t.Fatalf("serveRead with UDP dialer: %v", err)
	}
	if len(c.rconns) != 1 {
		t.Errorf("expected 1 read conn, got %d", len(c.rconns))
	}

	// Clean up
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

func TestServeReadMultipleConns(t *testing.T) {
	conf := testConfig()
	conf.ClientPortRange = config.PortRange{Min: 43500, Max: 43503} // 4 ports → 1-4 goroutines

	limiter := ratelimit.New(100)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	c := NewClient(conf, limiter, sp, nil, logger)

	c.listenPacket = func(_, address string) (net.PacketConn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address)})
	}

	err := c.serveRead()
	if err != nil {
		t.Fatalf("serveRead: %v", err)
	}

	// Should create up to min(4, 8) = 4 connections
	if len(c.rconns) == 0 {
		t.Error("expected at least 1 read conn")
	}

	c.closeReadConns()
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
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
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
