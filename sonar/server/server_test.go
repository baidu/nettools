package server

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/baidu/nettools/sonar/codec"
	"github.com/baidu/nettools/sonar/config"
	"github.com/baidu/nettools/stat"
)

func testServerConfig(port int) *config.Config {
	return &config.Config{
		Role:            config.RoleServer,
		ClientAddrs:     []string{"127.0.0.1"},
		ServerAddrs:     []string{"127.0.0.1"},
		TOS:             0,
		ClientPortRange: config.PortRange{Min: 43500, Max: 43509},
		ServerPortRange: config.PortRange{Min: port, Max: port},
		RateInSpan:      100,
		Span:            time.Second,
		Delay:           100 * time.Millisecond,
		MsgLen:          64,
	}
}

func findFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return port
}

func TestNew(t *testing.T) {
	conf := testServerConfig(0)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	s := New(conf, sp, nil, logger)

	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if len(s.salts) != 4 {
		t.Errorf("expected 4 salts, got %d", len(s.salts))
	}
	if len(s.stats) != 1 {
		t.Errorf("expected 1 stat entry, got %d", len(s.stats))
	}
	if _, ok := s.stats["127.0.0.1"]; !ok {
		t.Error("expected stat entry for client 127.0.0.1")
	}
}

func TestNewMinimumMsgLen(t *testing.T) {
	conf := testServerConfig(0)
	conf.MsgLen = 10
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	s := New(conf, sp, nil, logger)

	if s.conf.MsgLen != codec.MsgHeaderLen {
		t.Errorf("MsgLen = %d, want %d", s.conf.MsgLen, codec.MsgHeaderLen)
	}
}

func TestNewSaltPatterns(t *testing.T) {
	conf := testServerConfig(0)
	conf.MsgLen = 128
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	s := New(conf, sp, nil, logger)

	saltLen := 128 - codec.MsgHeaderLen

	// Salt 0: all 0xFF
	for _, b := range s.salts[0] {
		if b != 0xFF {
			t.Error("salt[0] should be all 0xFF")
			break
		}
	}
	// Salt 3: matches complementary alternating pattern
	expected := codec.ComplementaryBytes(saltLen)
	if !bytes.Equal(s.salts[3], expected) {
		t.Error("salt[3] should match codec.ComplementaryBytes")
	}
}

func TestNewMultipleClients(t *testing.T) {
	conf := testServerConfig(0)
	conf.ClientAddrs = []string{"10.0.0.1", "10.0.0.2"}
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	s := New(conf, sp, nil, logger)

	if len(s.stats) != 2 {
		t.Errorf("expected 2 stat entries, got %d", len(s.stats))
	}
}

func startTestServer(t *testing.T, port int) (*Server, context.CancelFunc) {
	t.Helper()
	conf := testServerConfig(port)
	sp := stat.NewProcessor(time.Second, 100*time.Millisecond)
	logger := log.New(io.Discard, "", 0)
	s := New(conf, sp, nil, logger)

	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	return s, cancel
}

func TestServerEcho(t *testing.T) {
	port := findFreePort(t)
	s, cancel := startTestServer(t, port)
	defer cancel()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	seq := uint64(42)
	ts := time.Now().UnixNano()
	salt := s.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, s.conf.MsgLen, 100, 0, 0)

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 10240)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("echo mismatch:\n  sent: %x\n  recv: %x",
			payload[:min(len(payload), 32)], buf[:min(n, 32)])
	}

	if !codec.IsValid(buf[:n]) {
		t.Error("echoed packet should be valid")
	}

	gotSeq, gotTS, gotLastSent, _, _ := codec.Decode(buf[:n])
	if gotSeq != seq {
		t.Errorf("seq: expected %d, got %d", seq, gotSeq)
	}
	if gotTS != ts {
		t.Errorf("ts: expected %d, got %d", ts, gotTS)
	}
	if gotLastSent != 100 {
		t.Errorf("lastSent: expected 100, got %d", gotLastSent)
	}
}

func TestServerEchoAllSaltPatterns(t *testing.T) {
	port := findFreePort(t)
	s, cancel := startTestServer(t, port)
	defer cancel()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	for i := 0; i < 4; i++ {
		seq := uint64(i)
		ts := time.Now().UnixNano()
		salt := s.salts[int(seq%4)]
		payload := codec.Encode(seq, salt, ts, s.conf.MsgLen, 50, 0, 0)

		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write salt %d: %v", i, err)
		}

		buf := make([]byte, 10240)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read echo salt %d: %v", i, err)
		}

		if !bytes.Equal(buf[:n], payload) {
			t.Errorf("salt %d: echo mismatch", i)
		}
	}
}

func TestServerInvalidPacket(t *testing.T) {
	port := findFreePort(t)
	_, cancel := startTestServer(t, port)
	defer cancel()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send garbage (no magic flag, too short)
	if _, err := conn.Write([]byte("garbage")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 10240)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected no echo for invalid packet")
	}
}

func TestServerShortPacket(t *testing.T) {
	port := findFreePort(t)
	_, cancel := startTestServer(t, port)
	defer cancel()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Packet with correct magic flag but too short for full header
	payload := append([]byte("CHAOOAHC"), make([]byte, 5)...)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 10240)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected no echo for short packet")
	}
}

func TestServerBitflipEcho(t *testing.T) {
	port := findFreePort(t)
	s, cancel := startTestServer(t, port)
	defer cancel()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Create a valid packet then corrupt the salt region
	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := s.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, s.conf.MsgLen, 100, 0, 0)
	payload[codec.MsgHeaderLen+3] ^= 0xFF

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Server should still echo the (corrupted) packet back
	buf := make([]byte, 10240)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected echo even with bitflip: %v", err)
	}

	// The echo should contain the corrupted data as-is
	if !bytes.Equal(buf[:n], payload) {
		t.Error("echo should match the sent (corrupted) payload")
	}
}

func TestServerRunCancel(t *testing.T) {
	port := findFreePort(t)
	s, cancel := startTestServer(t, port)

	// Verify server is responsive before cancel
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	seq := uint64(1)
	ts := time.Now().UnixNano()
	salt := s.salts[int(seq%4)]
	payload := codec.Encode(seq, salt, ts, s.conf.MsgLen, 100, 0, 0)
	_, _ = conn.Write(payload)

	buf := make([]byte, 10240)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("server should respond before cancel: %v", err)
	}

	// Cancel should stop the server without error
	cancel()
}
