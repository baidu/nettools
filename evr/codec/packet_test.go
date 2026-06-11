package codec

import (
	"bytes"
	"net"
	"testing"
)

func TestEncodeDecodeWithSrcIP(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAA}, 100)
	srcIP := net.ParseIP("10.20.30.40").To4()
	srcIPNum := uint32(srcIP[0])<<24 | uint32(srcIP[1])<<16 | uint32(srcIP[2])<<8 | uint32(srcIP[3])

	const (
		seq    = uint64(0x1122334455667788)
		ts     = int64(0x0102030405060708)
		msgLen = MsgHeaderLen + 100
	)

	data := EncodeWithSrcIP(seq, salt, ts, msgLen, srcIPNum)
	if len(data) != msgLen {
		t.Fatalf("encoded length = %d, want %d", len(data), msgLen)
	}
	if !IsValid(data) {
		t.Fatalf("IsValid returned false for freshly encoded payload")
	}
	if !bytes.Equal(data[:MagicFlagLen], magicFlag) {
		t.Fatalf("magic prefix mismatch: %q", data[:MagicFlagLen])
	}
	if !bytes.Equal(data[MsgHeaderLen:], salt) {
		t.Fatalf("salt body mismatch")
	}

	gotSeq, gotTS, gotIP := DecodeWithSrcIP(data)
	if gotSeq != seq {
		t.Errorf("seq = %#x, want %#x", gotSeq, seq)
	}
	if gotTS != ts {
		t.Errorf("ts = %#x, want %#x", gotTS, ts)
	}
	if !gotIP.Equal(srcIP) {
		t.Errorf("srcIP = %s, want %s", gotIP, srcIP)
	}
}

func TestEncodeWithSrcIPClampsMsgLen(t *testing.T) {
	data := EncodeWithSrcIP(1, nil, 0, 1, 0)
	if len(data) != MsgHeaderLen {
		t.Fatalf("len = %d, want %d (clamped to MsgHeaderLen)", len(data), MsgHeaderLen)
	}
}

func TestIsValid(t *testing.T) {
	if IsValid(nil) {
		t.Error("IsValid(nil) = true, want false")
	}
	if IsValid([]byte("short")) {
		t.Error("IsValid(too short) = true, want false")
	}
	bad := make([]byte, MsgHeaderLen)
	if IsValid(bad) {
		t.Error("IsValid(zero magic) = true, want false")
	}
}

func TestEncodeVxlanInner(t *testing.T) {
	innerIP := net.ParseIP("10.0.0.1").To4()
	payload := []byte("hello")
	pkt, err := EncodeVxlanInner(15990000, "00:00:00:00:ff:ff", "00:00:5e:00:01:ff",
		innerIP, innerIP, 9981, 8972, 64, 64, payload)
	if err != nil {
		t.Fatalf("EncodeVxlanInner: %v", err)
	}
	// VXLAN(8) + Eth(14) + IPv4(20) + UDP(8) + payload
	const minLen = 8 + 14 + 20 + 8 + 5
	if len(pkt) < minLen {
		t.Fatalf("packet len = %d, want >= %d", len(pkt), minLen)
	}
	if !bytes.Contains(pkt, payload) {
		t.Errorf("packet does not contain payload")
	}
}

func TestEncodeOuterUDP(t *testing.T) {
	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("10.0.0.2").To4()
	payload := []byte("payload-data")
	pkt, err := EncodeOuterUDP(src, dst, 9981, 4789, 64, 64, payload)
	if err != nil {
		t.Fatalf("EncodeOuterUDP: %v", err)
	}
	const minLen = 20 + 8 + 12
	if len(pkt) < minLen {
		t.Fatalf("packet len = %d, want >= %d", len(pkt), minLen)
	}
	if !bytes.Contains(pkt, payload) {
		t.Errorf("packet does not contain payload")
	}
}
