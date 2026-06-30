package traceroute6

import (
	"net"
	"testing"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func mustV6(s string) net.IP {
	ip := parseV6(s)
	if ip == nil {
		panic("bad test IPv6: " + s)
	}
	return ip
}

// buildInnerError builds an ICMPv6 error reply (Time Exceeded / Dest
// Unreachable) from a router, embedding the original probe in the Raw layer —
// mimicking what goscapy dissects off the wire. ICMPv6 errors carry a 4-byte
// unused field after the base header, then as much of the invoking packet as
// fits; routers quote the original IPv6 header (40 bytes) plus leading L4 bytes.
func buildInnerError(icmpType uint8, routerIP net.IP, original *packet.Packet) *packet.Packet {
	origBytes, err := original.Build()
	if err != nil {
		panic(err)
	}

	ip := layers.NewIPv6()
	_ = ip.Set("src", routerIP)
	_ = ip.Set("dst", mustV6("2001:db8::99"))
	_ = ip.Set("nh", layers.IPv6NextHdrICMP)
	icmp := layers.NewICMPv6()
	_ = icmp.Set("type", icmpType)
	_ = icmp.Set("code", uint8(0))
	pkt := ip.Over(icmp)
	raw := layers.NewRaw()
	// 4-byte unused field of the ICMPv6 error, then the quoted original packet.
	quote := append([]byte{0, 0, 0, 0}, origBytes...)
	_ = raw.Set("load", quote)
	pkt.Push(raw)

	wire, err := pkt.Build()
	if err != nil {
		panic(err)
	}
	dissected, err := packet.DissectByProto(wire, "IPv6")
	if err != nil {
		panic(err)
	}
	return dissected
}

func TestMatcherICMPv6TimeExceeded(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434})
	dst := mustV6("2001:4860:4860::8888")
	sent := tr.buildProbe(mustV6("2001:db8::1"), dst, 5, 0)

	reply := buildInnerError(layers.ICMPv6TimeExceed, mustV6("2001:db8:ffff::1"), sent)
	match := buildMatcher(ProtoICMP, dst)
	if !match(sent, reply) {
		t.Errorf("matcher should accept ICMPv6 Time Exceeded quoting our probe")
	}

	other := tr.buildProbe(mustV6("2001:db8::1"), mustV6("2606:4700:4700::1111"), 5, 0)
	otherReply := buildInnerError(layers.ICMPv6TimeExceed, mustV6("2001:db8:ffff::1"), other)
	if match(sent, otherReply) {
		t.Errorf("matcher should reject reply quoting a different destination")
	}
}

func TestMatcherUDPDestUnreachable(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoUDP, Port: 33434})
	dst := mustV6("2001:4860:4860::8888")
	sent := tr.buildProbe(mustV6("2001:db8::1"), dst, 7, 1)

	reply := buildInnerError(layers.ICMPv6DestUnreach, dst, sent)
	match := buildMatcher(ProtoUDP, dst)
	if !match(sent, reply) {
		t.Errorf("matcher should accept ICMPv6 Dest Unreachable for UDP probe")
	}

	_, reached := extractReply(ProtoUDP, reply)
	if !reached {
		t.Errorf("UDP Dest Unreachable should mark reached")
	}
}

func TestBuildProbeProtocols(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434, TrafficClass: 16})
	src, dst := mustV6("2001:db8::1"), mustV6("2001:4860:4860::8888")

	icmp := tr.buildProbe(src, dst, 3, 0)
	if icmp.GetLayer("ICMPv6") == nil {
		t.Errorf("ICMPv6 probe missing ICMPv6 layer")
	}
	if hlim, _ := icmp.GetLayer("IPv6").Get("hlim"); hlim != uint8(3) {
		t.Errorf("hlim not set, got %v", hlim)
	}
	verVal, _ := icmp.GetLayer("IPv6").Get("ver_tc_fl")
	if tc := layers.IPv6TrafficClass(verVal.(uint32)); tc != 16 {
		t.Errorf("traffic class not set, got %v", tc)
	}

	tr.conf.Protocol = ProtoUDP
	udp := tr.buildProbe(src, dst, 4, 0)
	if udp.GetLayer("UDP") == nil {
		t.Errorf("UDP probe missing UDP layer")
	}
	if dp, _ := udp.GetLayer("UDP").Get("dport"); dp != uint16(33434+4) {
		t.Errorf("UDP dport should increment with hop limit, got %v", dp)
	}

	tr.conf.Protocol = ProtoTCP
	tr.conf.Port = 443
	tcp := tr.buildProbe(src, dst, 5, 0)
	if tcp.GetLayer("TCP") == nil {
		t.Errorf("TCP probe missing TCP layer")
	}
	if flags, _ := tcp.GetLayer("TCP").Get("flags"); flags != layers.TCPSyn {
		t.Errorf("TCP probe should set SYN flag, got %v", flags)
	}
	if dp, _ := tcp.GetLayer("TCP").Get("dport"); dp != uint16(443) {
		t.Errorf("TCP dport = %v, want 443", dp)
	}
}

func TestBuildProbePortOverrides(t *testing.T) {
	src, dst := mustV6("2001:db8::1"), mustV6("2001:4860:4860::8888")

	tr := NewTracer(&Config{Protocol: ProtoUDP, Port: 33434, SrcPort: 12345, FixedDstPort: true})
	udp := tr.buildProbe(src, dst, 7, 2)
	if sp, _ := udp.GetLayer("UDP").Get("sport"); sp != uint16(12345) {
		t.Errorf("UDP sport = %v, want fixed 12345", sp)
	}
	if dp, _ := udp.GetLayer("UDP").Get("dport"); dp != uint16(33434) {
		t.Errorf("UDP dport = %v, want fixed 33434", dp)
	}

	tr.conf.FixedDstPort = false
	udp2 := tr.buildProbe(src, dst, 7, 0)
	if dp, _ := udp2.GetLayer("UDP").Get("dport"); dp != uint16(33434+7) {
		t.Errorf("UDP dport = %v, want 33441", dp)
	}

	trTCP := NewTracer(&Config{Protocol: ProtoTCP, Port: 80, SrcPort: 6000})
	tcp := trTCP.buildProbe(src, dst, 3, 1)
	if sp, _ := tcp.GetLayer("TCP").Get("sport"); sp != uint16(6000) {
		t.Errorf("TCP sport = %v, want fixed 6000", sp)
	}
}

func TestExtractReplyEchoReply(t *testing.T) {
	ip := layers.NewIPv6()
	_ = ip.Set("src", mustV6("2001:4860:4860::8888"))
	_ = ip.Set("dst", mustV6("2001:db8::1"))
	_ = ip.Set("nh", layers.IPv6NextHdrICMP)
	icmp := layers.NewICMPv6()
	_ = icmp.Set("type", layers.ICMPv6EchoReply)
	echo := layers.NewICMPv6EchoReply(1, 1)
	pkt := ip.Over(icmp)
	pkt.Push(echo)
	wire, _ := pkt.Build()
	d, _ := packet.DissectByProto(wire, "IPv6")

	from, reached := extractReply(ProtoICMP, d)
	if !reached {
		t.Errorf("echo reply should mark reached")
	}
	if from == nil || !from.Equal(mustV6("2001:4860:4860::8888")) {
		t.Errorf("from = %v, want 2001:4860:4860::8888", from)
	}
}

// buildEchoReply builds an ICMPv6 Echo Reply from the destination echoing the
// given id+seq — what a real target returns for our probe.
func buildEchoReply(src net.IP, id, seq uint16) *packet.Packet {
	ip := layers.NewIPv6()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", mustV6("2001:db8::99"))
	_ = ip.Set("nh", layers.IPv6NextHdrICMP)
	icmp := layers.NewICMPv6()
	_ = icmp.Set("type", layers.ICMPv6EchoReply)
	echo := layers.NewICMPv6EchoReply(id, seq)
	pkt := ip.Over(icmp)
	pkt.Push(echo)
	wire, err := pkt.Build()
	if err != nil {
		panic(err)
	}
	d, err := packet.DissectByProto(wire, "IPv6")
	if err != nil {
		panic(err)
	}
	return d
}

// TestMatcherEchoReplyIdentity guards against misattributing a single Echo
// Reply to every concurrent probe: the matcher must only accept the reply whose
// id+seq match the probe that was sent.
func TestMatcherEchoReplyIdentity(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434})
	dst := mustV6("2001:4860:4860::8888")
	match := buildMatcher(ProtoICMP, dst)

	sent := tr.buildProbe(mustV6("2001:db8::1"), dst, 4, 0)
	sentSeq := uint16(4) << 8

	good := buildEchoReply(dst, tr.pid, sentSeq)
	if !match(sent, good) {
		t.Errorf("matcher should accept echo reply with matching id+seq")
	}

	wrong := buildEchoReply(dst, tr.pid, uint16(1)<<8)
	if match(sent, wrong) {
		t.Errorf("matcher must reject echo reply whose seq belongs to another probe")
	}
}
