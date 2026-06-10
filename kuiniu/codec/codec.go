package codec

import (
	"bytes"
	"encoding/binary"
)

const (
	magicFlagLen = 8
	// MsgHeaderLen = magic(8) + seq(8) + ts(8) + lastSent(4) + srcIP(4) + dstIP(4) + srcPort(2) + dstPort(2) + lssp(2) + lsdp(2)
	MsgHeaderLen = magicFlagLen + 8 + 8 + 4 + 4 + 4 + 2 + 2 + 2 + 2 // 44 bytes
)

var magicFlag = []byte("KUINIUTC")

// Encode builds a kuiniu probe packet with the given sequence, timestamp,
// source/destination IP and port, last-sent count, and last span's starting ports.
// The remaining bytes are filled with salt padding.
func Encode(seq uint64, salt []byte, ts int64, msgLen int,
	srcIP, dstIP []byte, srcPort, dstPort uint16,
	lastSentCount uint32, lastStartSrcPort, lastStartDstPort uint16,
) []byte {
	if msgLen < MsgHeaderLen {
		msgLen = MsgHeaderLen
	}
	saltLen := msgLen - MsgHeaderLen
	data := make([]byte, msgLen)

	off := 0
	copy(data[off:off+magicFlagLen], magicFlag)
	off += magicFlagLen
	binary.BigEndian.PutUint64(data[off:off+8], seq)
	off += 8
	binary.BigEndian.PutUint64(data[off:off+8], uint64(ts))
	off += 8
	binary.BigEndian.PutUint32(data[off:off+4], lastSentCount)
	off += 4
	copy(data[off:off+4], srcIP)
	off += 4
	copy(data[off:off+4], dstIP)
	off += 4
	binary.BigEndian.PutUint16(data[off:off+2], srcPort)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], dstPort)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], lastStartSrcPort)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], lastStartDstPort)

	if saltLen > 0 {
		n := min(saltLen, len(salt))
		copy(data[MsgHeaderLen:MsgHeaderLen+n], salt[:n])
	}

	return data
}

// DecodeResult holds all fields extracted from a kuiniu probe packet.
type DecodeResult struct {
	Seq              uint64
	Ts               int64
	LastSentCount    uint32
	SrcIP            []byte
	DstIP            []byte
	SrcPort          uint16
	DstPort          uint16
	LastStartSrcPort uint16
	LastStartDstPort uint16
}

// Decode extracts all fields from a kuiniu probe packet payload.
// Returns zero values if data is too short.
func Decode(data []byte) DecodeResult {
	if len(data) < MsgHeaderLen {
		return DecodeResult{}
	}

	var r DecodeResult
	off := magicFlagLen
	r.Seq = binary.BigEndian.Uint64(data[off : off+8])
	off += 8
	r.Ts = int64(binary.BigEndian.Uint64(data[off : off+8]))
	off += 8
	r.LastSentCount = binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	r.SrcIP = make([]byte, 4)
	copy(r.SrcIP, data[off:off+4])
	off += 4
	r.DstIP = make([]byte, 4)
	copy(r.DstIP, data[off:off+4])
	off += 4
	r.SrcPort = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	r.DstPort = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	r.LastStartSrcPort = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	r.LastStartDstPort = binary.BigEndian.Uint16(data[off : off+2])

	return r
}

// IsValid checks whether the given byte slice starts with the kuiniu
// magic flag and is long enough to contain a full header.
func IsValid(data []byte) bool {
	if len(data) < MsgHeaderLen {
		return false
	}
	return bytes.Equal(magicFlag, data[:magicFlagLen])
}
