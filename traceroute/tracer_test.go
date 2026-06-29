package traceroute

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

func mustIP(s string) net.IP {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		panic("bad test IP: " + s)
	}
	return ip
}

func TestFormatRTT(t *testing.T) {
	if got := formatRTT(1500 * time.Microsecond); got != "1.500ms" {
		t.Errorf("formatRTT = %q, want 1.500ms", got)
	}
}

func TestResultStringHeaderAndHops(t *testing.T) {
	r := &Result{
		Dst:     "example.com",
		DstIP:   mustIP("93.184.216.34"),
		Proto:   ProtoICMP,
		MaxHops: 30,
		Hops: []Hop{
			{
				TTL:   1,
				Addrs: []net.IP{mustIP("192.168.1.1")},
				Hosts: []string{"gateway"},
				Probes: []ProbeResult{
					{FromIP: mustIP("192.168.1.1"), RTT: 1234 * time.Microsecond},
				},
			},
			{
				TTL:    2,
				Probes: []ProbeResult{{TimedOut: true}, {TimedOut: true}},
			},
		},
	}

	out := r.String()
	if !strings.HasPrefix(out, "traceroute to example.com (93.184.216.34), 30 hops max, ICMP probes") {
		t.Errorf("unexpected header: %q", out)
	}
	if !strings.Contains(out, "gateway (192.168.1.1)") {
		t.Errorf("expected hostname+ip, got: %q", out)
	}
	if !strings.Contains(out, "1.234ms") {
		t.Errorf("expected formatted RTT, got: %q", out)
	}
	// Hop 2 fully timed out → two stars.
	if !strings.Contains(out, "2   * *") {
		t.Errorf("expected timeout stars for hop 2, got: %q", out)
	}
}

func TestResultSummary(t *testing.T) {
	r := &Result{
		Hops: []Hop{{
			TTL:   1,
			Addrs: []net.IP{mustIP("10.0.0.1")},
			Probes: []ProbeResult{
				{RTT: 2 * time.Millisecond},
				{TimedOut: true},
			},
		}},
	}
	s := r.Summary()
	if !strings.Contains(s, "ttl=1") || !strings.Contains(s, "10.0.0.1") {
		t.Errorf("summary missing fields: %q", s)
	}
	if !strings.Contains(s, "loss=50%") {
		t.Errorf("summary loss wrong: %q", s)
	}
}

// buildInnerError builds an ICMP error reply (Time Exceeded / Dest Unreachable)
// from a router, embedding the original probe's IP+L4 header in the Raw layer —
// mimicking what goscapy would dissect off the wire.
func buildInnerError(icmpType uint8, routerIP net.IP, original *packet.Packet) *packet.Packet {
	origBytes, err := original.Build()
	if err != nil {
		panic(err)
	}
	// Routers quote the original IP header + first 8 bytes of payload.
	quote := origBytes
	if len(quote) > 28 {
		quote = quote[:28]
	}

	ip := layers.NewIP()
	_ = ip.Set("src", routerIP)
	_ = ip.Set("dst", mustIP("10.0.0.99"))
	_ = ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMP()
	_ = icmp.Set("type", icmpType)
	_ = icmp.Set("code", uint8(0))
	pkt := ip.Over(icmp)
	raw := layers.NewRaw()
	_ = raw.Set("load", quote)
	pkt.Push(raw)

	// Round-trip through Build/Dissect so the matcher sees realistic layers.
	wire, err := pkt.Build()
	if err != nil {
		panic(err)
	}
	dissected, err := packet.DissectByProto(wire, "IP")
	if err != nil {
		panic(err)
	}
	return dissected
}

func TestMatcherICMPTimeExceeded(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434})
	dst := mustIP("8.8.8.8")
	sent := tr.buildProbe(mustIP("10.0.0.99"), dst, 5, 0)

	reply := buildInnerError(11, mustIP("100.64.0.1"), sent)
	match := buildMatcher(ProtoICMP, dst)
	if !match(sent, reply) {
		t.Errorf("matcher should accept ICMP Time Exceeded quoting our probe")
	}

	// A reply quoting a different destination must not match.
	other := tr.buildProbe(mustIP("10.0.0.99"), mustIP("1.1.1.1"), 5, 0)
	otherReply := buildInnerError(11, mustIP("100.64.0.1"), other)
	if match(sent, otherReply) {
		t.Errorf("matcher should reject reply quoting different destination")
	}
}

func TestMatcherUDPPortUnreachable(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoUDP, Port: 33434})
	dst := mustIP("8.8.8.8")
	sent := tr.buildProbe(mustIP("10.0.0.99"), dst, 7, 1)

	reply := buildInnerError(3, dst, sent)
	match := buildMatcher(ProtoUDP, dst)
	if !match(sent, reply) {
		t.Errorf("matcher should accept ICMP Dest Unreachable for UDP probe")
	}

	_, reached := extractReply(ProtoUDP, reply)
	if !reached {
		t.Errorf("UDP Dest Unreachable should mark reached")
	}
}

func TestBuildProbeProtocols(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434, TOS: 16})
	src, dst := mustIP("10.0.0.1"), mustIP("8.8.8.8")

	icmp := tr.buildProbe(src, dst, 3, 0)
	if icmp.GetLayer("ICMP") == nil {
		t.Errorf("ICMP probe missing ICMP layer")
	}
	if ttl, _ := icmp.GetLayer("IP").Get("ttl"); ttl != uint8(3) {
		t.Errorf("ttl not set, got %v", ttl)
	}
	if tos, _ := icmp.GetLayer("IP").Get("tos"); tos != uint8(16) {
		t.Errorf("tos not set, got %v", tos)
	}

	tr.conf.Protocol = ProtoUDP
	udp := tr.buildProbe(src, dst, 4, 0)
	if udp.GetLayer("UDP") == nil {
		t.Errorf("UDP probe missing UDP layer")
	}
	if dp, _ := udp.GetLayer("UDP").Get("dport"); dp != uint16(33434+4) {
		t.Errorf("UDP dport should increment with ttl, got %v", dp)
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
	src, dst := mustIP("10.0.0.1"), mustIP("8.8.8.8")

	// Fixed source port + fixed destination port for UDP.
	tr := NewTracer(&Config{Protocol: ProtoUDP, Port: 33434, SrcPort: 12345, FixedDstPort: true})
	udp := tr.buildProbe(src, dst, 7, 2)
	if sp, _ := udp.GetLayer("UDP").Get("sport"); sp != uint16(12345) {
		t.Errorf("UDP sport = %v, want fixed 12345", sp)
	}
	if dp, _ := udp.GetLayer("UDP").Get("dport"); dp != uint16(33434) {
		t.Errorf("UDP dport = %v, want fixed 33434 (no per-hop increment)", dp)
	}

	// Without FixedDstPort, dport increments with ttl.
	tr.conf.FixedDstPort = false
	udp2 := tr.buildProbe(src, dst, 7, 0)
	if dp, _ := udp2.GetLayer("UDP").Get("dport"); dp != uint16(33434+7) {
		t.Errorf("UDP dport = %v, want 33441", dp)
	}

	// Fixed source port for TCP.
	trTCP := NewTracer(&Config{Protocol: ProtoTCP, Port: 80, SrcPort: 6000})
	tcp := trTCP.buildProbe(src, dst, 3, 1)
	if sp, _ := tcp.GetLayer("TCP").Get("sport"); sp != uint16(6000) {
		t.Errorf("TCP sport = %v, want fixed 6000", sp)
	}
}

func TestBuildProbeSrcDstIPOverride(t *testing.T) {
	// The IP override happens in Run/traceTarget, but buildProbe writes whatever
	// src/dst it is handed — verify the bytes land in the IP header.
	tr := NewTracer(&Config{Protocol: ProtoUDP, Port: 33434})
	pkt := tr.buildProbe(mustIP("192.0.2.7"), mustIP("198.51.100.9"), 2, 0)
	ip := pkt.GetLayer("IP")
	srcVal, _ := ip.Get("src")
	dstVal, _ := ip.Get("dst")
	if s, _ := srcVal.(net.IP); s == nil || !s.Equal(mustIP("192.0.2.7")) {
		t.Errorf("probe src = %v, want 192.0.2.7", srcVal)
	}
	if d, _ := dstVal.(net.IP); d == nil || !d.Equal(mustIP("198.51.100.9")) {
		t.Errorf("probe dst = %v, want 198.51.100.9", dstVal)
	}
}

func TestConfigValidatePortIPOverrides(t *testing.T) {
	base := func() *Config {
		c := DefaultConfig()
		c.Targets = []string{"8.8.8.8"}
		c.Protocol = ProtoUDP
		return c
	}
	good := base()
	good.SrcPort = 12345
	good.SrcIP = "10.0.0.5"
	good.DstIP = "8.8.4.4"
	if err := good.Validate(); err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}

	bad := base()
	bad.SrcIP = "not-an-ip"
	if err := bad.Validate(); err == nil {
		t.Errorf("expected error for invalid src-ip")
	}

	icmp := base()
	icmp.Protocol = ProtoICMP
	icmp.SrcPort = 1000
	if err := icmp.Validate(); err == nil {
		t.Errorf("expected error: src-port on icmp")
	}
}

func TestExtractReplyEchoReply(t *testing.T) {
	ip := layers.NewIP()
	_ = ip.Set("src", mustIP("8.8.8.8"))
	_ = ip.Set("dst", mustIP("10.0.0.1"))
	_ = ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMP()
	_ = icmp.Set("type", uint8(0)) // Echo Reply
	pkt := ip.Over(icmp)
	wire, _ := pkt.Build()
	d, _ := packet.DissectByProto(wire, "IP")

	from, reached := extractReply(ProtoICMP, d)
	if !reached {
		t.Errorf("echo reply should mark reached")
	}
	if from == nil || from.String() != "8.8.8.8" {
		t.Errorf("from = %v, want 8.8.8.8", from)
	}
}

// buildEchoReply builds an ICMP Echo Reply from the destination echoing the
// given id+seq — what a real target returns for our probe.
func buildEchoReply(src net.IP, id, seq uint16) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("src", src)
	_ = ip.Set("dst", mustIP("10.0.0.99"))
	_ = ip.Set("proto", layers.IPProtoICMP)
	icmp := layers.NewICMP()
	_ = icmp.Set("type", uint8(0))
	_ = icmp.Set("id", id)
	_ = icmp.Set("seq", seq)
	wire, err := ip.Over(icmp).Build()
	if err != nil {
		panic(err)
	}
	d, err := packet.DissectByProto(wire, "IP")
	if err != nil {
		panic(err)
	}
	return d
}

// TestMatcherEchoReplyIdentity guards against the misattribution bug where a
// single Echo Reply from the destination matched every concurrent probe. The
// matcher must only accept the reply whose id+seq match the probe that was sent.
func TestMatcherEchoReplyIdentity(t *testing.T) {
	tr := NewTracer(&Config{Protocol: ProtoICMP, Port: 33434})
	dst := mustIP("8.8.8.8")
	match := buildMatcher(ProtoICMP, dst)

	// Probe sent at ttl=4, probe=0 → id=pid, seq=(4<<8|0).
	sent := tr.buildProbe(mustIP("10.0.0.99"), dst, 4, 0)
	sentSeq := uint16(4) << 8

	// Correct reply (matching id+seq) is accepted.
	good := buildEchoReply(dst, tr.pid, sentSeq)
	if !match(sent, good) {
		t.Errorf("matcher should accept echo reply with matching id+seq")
	}

	// Reply echoing a different seq (i.e. for a different TTL's probe) must be
	// rejected — otherwise it would be misattributed to this probe.
	wrong := buildEchoReply(dst, tr.pid, uint16(1)<<8)
	if match(sent, wrong) {
		t.Errorf("matcher must reject echo reply whose seq belongs to another probe")
	}
}
