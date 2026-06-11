// Package codec implements encoding and decoding for the EVR VXLAN probe.
//
// The probe packet is an outer IPv4/UDP datagram (delivered to a VTEP on
// UDP port 4789) carrying a VXLAN-encapsulated inner Ethernet/IPv4/UDP
// frame whose payload is a small protocol message: an 8-byte magic flag
// "EVRCHECK", followed by seq (8 bytes), timestamp (8 bytes) and a 4-byte
// embedded inner source IP, padded with a salt pattern. The trick of the
// probe is that the inner src IP and inner dst IP are both set to the
// probing machine's address, while the inner src IP is also encoded in
// the payload so the response can be matched back to the original target.
package codec

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/smallnest/goscapy/pkg/goscapy"
	gslayers "github.com/smallnest/goscapy/pkg/layers"
)

const (
	// MagicFlagLen is the length of the magic prefix.
	MagicFlagLen = 8
	// MsgHeaderLen is the length of the fixed protocol header
	// (magic + seq + ts + srcIP).
	MsgHeaderLen = MagicFlagLen + 20
)

var magicFlag = []byte("EVRCHECK")

// EncodeWithSrcIP builds the inner UDP payload: magic + seq + ts + srcIP +
// salt-padded body. msgLen is clamped to at least MsgHeaderLen.
func EncodeWithSrcIP(seq uint64, salt []byte, ts int64, msgLen int, srcIP uint32) []byte {
	if msgLen < MsgHeaderLen {
		msgLen = MsgHeaderLen
	}
	saltLen := msgLen - MsgHeaderLen
	data := make([]byte, msgLen)
	copy(data, magicFlag)
	binary.BigEndian.PutUint64(data[MagicFlagLen:MagicFlagLen+8], seq)
	binary.BigEndian.PutUint64(data[MagicFlagLen+8:MagicFlagLen+16], uint64(ts))
	binary.BigEndian.PutUint32(data[MagicFlagLen+16:MagicFlagLen+20], srcIP)
	if saltLen > 0 {
		copy(data[MagicFlagLen+20:], salt)
	}
	return data
}

// DecodeWithSrcIP extracts seq, ts and the embedded inner source IP from a payload.
func DecodeWithSrcIP(data []byte) (seq uint64, ts int64, srcIP net.IP) {
	if len(data) < MsgHeaderLen {
		return
	}
	seq = binary.BigEndian.Uint64(data[MagicFlagLen : MagicFlagLen+8])
	ts = int64(binary.BigEndian.Uint64(data[MagicFlagLen+8 : MagicFlagLen+16]))
	srcIP = make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, binary.BigEndian.Uint32(data[MagicFlagLen+16:MagicFlagLen+20]))
	return
}

// IsValid checks whether the payload starts with the magic prefix and is
// long enough to contain the full header.
func IsValid(data []byte) bool {
	if len(data) < MsgHeaderLen {
		return false
	}
	return bytes.Equal(magicFlag, data[:MagicFlagLen])
}

// EncodeVxlanInner builds the VXLAN inner part: VXLAN | Ethernet | IPv4 | UDP | payload.
// It is intended to be wrapped by an outer UDP packet via EncodeOuterUDP.
func EncodeVxlanInner(vni uint32, srcMAC, dstMAC string, innerSrcIP, innerDstIP net.IP,
	innerSrcPort, innerDstPort uint16, tos uint8, ttl int, payload []byte,
) ([]byte, error) {
	pb := goscapy.NewVXLAN().VNI(vni).
		Over(goscapy.NewEthernet().SrcMAC(srcMAC).DstMAC(dstMAC).Type(gslayers.EtherTypeIPv4)).
		Over(goscapy.NewIP().
			SrcIP(innerSrcIP.String()).
			DstIP(innerDstIP.String()).
			TTL(uint8(ttl)).
			Proto(gslayers.IPProtoUDP)).
		Over(goscapy.NewUDP().SrcPort(innerSrcPort).DstPort(innerDstPort))
	if tos != 0 {
		_ = pb.Packet().GetLayers("IP")[0].Set("tos", tos)
	}
	pb.Packet().Push(gslayers.NewRawWith(payload))
	return pb.Build()
}

// EncodeOuterUDP builds an outer IPv4/UDP packet with the given payload.
// The IP layer is included so the kernel does not rewrite the source IP
// (raw sockets opened with "ip4:udp" deliver the IP header as well).
func EncodeOuterUDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, tos uint8, ttl int, payload []byte) ([]byte, error) {
	pb := goscapy.NewIP().
		SrcIP(srcIP.String()).
		DstIP(dstIP.String()).
		TTL(uint8(ttl)).
		Proto(gslayers.IPProtoUDP).
		Over(goscapy.NewUDP().SrcPort(srcPort).DstPort(dstPort))
	if tos != 0 {
		_ = pb.Packet().GetLayers("IP")[0].Set("tos", tos)
	}
	pb.Packet().Push(gslayers.NewRawWith(payload))
	return pb.Build()
}

// EncodeUDPOnly builds a UDP header + payload for use with raw "ip4:udp"
// sockets, where the kernel writes the IP header automatically. It mirrors
// sonar/codec.EncodeUDPPacket.
func EncodeUDPOnly(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl int, payload []byte) ([]byte, error) {
	pb := goscapy.NewIP().
		SrcIP(srcIP.String()).
		DstIP(dstIP.String()).
		TTL(uint8(ttl)).
		Over(goscapy.NewUDP().SrcPort(srcPort).DstPort(dstPort))
	pb.Packet().Push(gslayers.NewRawWith(payload))
	return pb.Packet().BuildFrom(1)
}
