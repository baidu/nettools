package traceroute6

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Tracer runs traceroute6 probes for one or more targets.
type Tracer struct {
	conf *Config
	pid  uint16
}

// NewTracer creates a Tracer with the given configuration.
func NewTracer(conf *Config) *Tracer {
	return &Tracer{conf: conf, pid: pid()}
}

// Run traces all configured targets concurrently and returns one Result per
// target, in the same order as conf.Targets. Reverse-DNS resolution (if
// enabled) runs once over all hops after probing completes.
func (t *Tracer) Run() ([]*Result, error) {
	results := make([]*Result, len(t.conf.Targets))

	sem := make(chan struct{}, t.conf.Parallel)

	var targetWG sync.WaitGroup
	for ti, dst := range t.conf.Targets {
		dstIP := parseV6(dst)
		if dstIP == nil {
			results[ti] = &Result{Dst: dst, Proto: t.conf.Protocol, MaxHops: t.conf.HopLimit}
			continue
		}

		probeDst := dstIP
		if t.conf.DstIP != "" {
			if ip := parseV6(t.conf.DstIP); ip != nil {
				probeDst = ip
			} else {
				return nil, fmt.Errorf("invalid destination IPv6 address: %q", t.conf.DstIP)
			}
		}

		srcIP, iface, err := localEndpoint(t.conf, probeDst)
		if err != nil {
			return nil, err
		}
		if t.conf.SrcIP != "" {
			if ip := parseV6(t.conf.SrcIP); ip != nil {
				srcIP = ip
			} else {
				return nil, fmt.Errorf("invalid source IPv6 address: %q", t.conf.SrcIP)
			}
		}

		targetWG.Add(1)
		go func(idx int, dst string, dstIP, probeDst, srcIP net.IP, iface string) {
			defer targetWG.Done()
			results[idx] = t.traceTarget(dst, dstIP, probeDst, srcIP, iface, sem)
		}(ti, dst, dstIP, probeDst, srcIP, iface)
	}
	targetWG.Wait()

	if t.conf.ResolveDNS {
		resolveHosts(results)
	}
	if len(t.conf.Providers) > 0 {
		enrichHops(context.Background(), t.conf.Providers, results)
	}
	return results, nil
}

// parseV6 returns the 16-byte form of an IPv6 address string, or nil if s is
// not a (non-IPv4) IPv6 address.
func parseV6(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return nil
	}
	return ip.To16()
}

// traceTarget probes every Hop Limit for a single destination. All hops (and
// the probes within each) are sent concurrently, capped by sem; replies are
// matched back to their probe by goscapy's Sr1 matcher.
func (t *Tracer) traceTarget(dst string, dstIP, probeDst, srcIP net.IP, iface string, sem chan struct{}) *Result {
	res := &Result{
		Dst:     dst,
		DstIP:   dstIP,
		Proto:   t.conf.Protocol,
		MaxHops: t.conf.HopLimit,
		Hops:    make([]Hop, t.conf.HopLimit),
	}

	var wg sync.WaitGroup
	for ttl := 1; ttl <= t.conf.HopLimit; ttl++ {
		res.Hops[ttl-1].TTL = ttl
		for probe := 0; probe < t.conf.Queries; probe++ {
			wg.Add(1)
			go func(ttl, probe int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				pr := t.sendProbe(srcIP, probeDst, iface, ttl, probe)
				t.appendProbe(&res.Hops[ttl-1], pr)
			}(ttl, probe)
		}
	}
	wg.Wait()

	t.finalize(res)
	return res
}

var probeMu sync.Mutex

// appendProbe records a probe result on a hop, recording any new responder IP.
func (t *Tracer) appendProbe(h *Hop, pr ProbeResult) {
	probeMu.Lock()
	defer probeMu.Unlock()
	h.Probes = append(h.Probes, pr)
	if pr.FromIP != nil {
		h.addAddr(pr.FromIP)
	}
}

// finalize marks whether the destination was reached and trims hops beyond it.
func (t *Tracer) finalize(res *Result) {
	lastReached := -1
	for i := range res.Hops {
		if res.Hops[i].Reached() {
			lastReached = i
			break
		}
	}
	if lastReached >= 0 {
		res.Reached = true
		res.Hops = res.Hops[:lastReached+1]
	}
}

// sendProbe builds, sends, and awaits a single probe at the given Hop Limit.
func (t *Tracer) sendProbe(srcIP, dstIP net.IP, iface string, ttl, probe int) ProbeResult {
	pkt := t.buildProbe(srcIP, dstIP, ttl, probe)
	match := buildMatcher(t.conf.Protocol, dstIP)

	start := time.Now()
	_, resp, err := sendrecv.Sr1(pkt, iface, t.conf.Timeout, match)
	rtt := time.Since(start)

	if err != nil || resp == nil {
		return ProbeResult{TimedOut: true}
	}

	from, reached := extractReply(t.conf.Protocol, resp)
	return ProbeResult{FromIP: from, RTT: rtt, Reached: reached}
}

// buildProbe constructs the probe packet for the configured protocol using
// goscapy layers. The probe is tagged so replies can be matched back:
//   - ICMPv6: id=pid, seq encodes ttl/probe
//   - UDP/TCP: source port encodes pid+probe, dest port identifies the flow
//
// The Hop Limit is set per call; the IPv6 Traffic Class (v6 analogue of TOS) is
// encoded into ver_tc_fl when non-zero.
func (t *Tracer) buildProbe(srcIP, dstIP net.IP, ttl, probe int) *packet.Packet {
	ip := layers.NewIPv6()
	_ = ip.Set("src", srcIP)
	_ = ip.Set("dst", dstIP)
	_ = ip.Set("hlim", uint8(ttl))
	if t.conf.TrafficClass != 0 {
		_ = ip.Set("ver_tc_fl", layers.MakeIPv6VerTCFL(uint8(t.conf.TrafficClass), 0))
	}

	switch t.conf.Protocol {
	case ProtoUDP:
		_ = ip.Set("nh", layers.IPv6NextHdrUDP)
		udp := layers.NewUDP()
		_ = udp.Set("sport", t.udpSrcPort(ttl, probe))
		_ = udp.Set("dport", t.dstPort(ttl))
		pkt := ip.Over(udp)
		raw := layers.NewRaw()
		_ = raw.Set("load", probePayload(ttl, probe))
		pkt.Push(raw)
		return pkt

	case ProtoTCP:
		_ = ip.Set("nh", layers.IPv6NextHdrTCP)
		tcp := layers.NewTCP()
		_ = tcp.Set("sport", t.tcpSrcPort(ttl, probe))
		_ = tcp.Set("dport", t.conf.Port)
		_ = tcp.Set("flags", layers.TCPSyn)
		_ = tcp.Set("seq", uint32(ttl)<<16|uint32(probe))
		return ip.Over(tcp)

	default: // ProtoICMP
		_ = ip.Set("nh", layers.IPv6NextHdrICMP)
		icmp := layers.NewICMPv6()
		echo := layers.NewICMPv6Echo(t.pid, uint16(ttl)<<8|uint16(probe&0xFF))
		pkt := ip.Over(icmp)
		pkt.Push(echo)
		return pkt
	}
}

// dstPort returns the destination port for a UDP probe. The classic UDP
// traceroute increments the port per Hop Limit; FixedDstPort pins it to Port.
func (t *Tracer) dstPort(ttl int) uint16 {
	if t.conf.FixedDstPort {
		return t.conf.Port
	}
	return t.conf.Port + uint16(ttl)
}

// udpSrcPort returns the UDP source port: the user's fixed SrcPort if set,
// otherwise a per-(ttl,probe) value for concurrent disambiguation.
func (t *Tracer) udpSrcPort(ttl, probe int) uint16 {
	if t.conf.SrcPort != 0 {
		return t.conf.SrcPort
	}
	return ephemeralSrcPort(t.pid, ttl, probe)
}

// tcpSrcPort returns the TCP source port: the user's fixed SrcPort if set,
// otherwise a per-(ttl,probe) value for concurrent disambiguation.
func (t *Tracer) tcpSrcPort(ttl, probe int) uint16 {
	if t.conf.SrcPort != 0 {
		return t.conf.SrcPort
	}
	return ephemeralSrcPort(t.pid, ttl, probe)
}

// probePayload returns a small deterministic UDP payload encoding ttl/probe.
func probePayload(ttl, probe int) []byte {
	return []byte{byte(ttl), byte(probe), 0x00, 0x00}
}

// ephemeralSrcPort derives a per-(ttl,probe) ephemeral source port from the pid
// so concurrent UDP/TCP probes can be told apart in quoted ICMPv6 error headers.
func ephemeralSrcPort(pid uint16, ttl, probe int) uint16 {
	return 33000 + (pid+uint16(ttl)*16+uint16(probe))%30000
}

// buildMatcher returns a goscapy MatchFunc that pairs a reply with the sent
// probe. It accepts ICMPv6 Time Exceeded / Destination Unreachable carrying our
// original packet, plus direct replies (Echo Reply, TCP SYN-ACK/RST) from the
// destination. All parsing of the embedded original packet uses goscapy layers.
func buildMatcher(proto Protocol, dstIP net.IP) sendrecv.MatchFunc {
	return func(sent, received *packet.Packet) bool {
		recvIP := received.GetLayer("IPv6")
		if recvIP == nil {
			return false
		}
		sentIP := sent.GetLayer("IPv6")
		if sentIP == nil {
			return false
		}
		sentDstVal, _ := sentIP.Get("dst")
		sentDst, _ := sentDstVal.(net.IP)
		if sentDst == nil {
			return false
		}

		recvICMP := received.GetLayer("ICMPv6")

		// Direct TCP reply from the destination (SYN-ACK or RST).
		if proto == ProtoTCP && recvICMP == nil {
			if recvTCP := received.GetLayer("TCP"); recvTCP != nil {
				recvSrcVal, _ := recvIP.Get("src")
				recvSrc, _ := recvSrcVal.(net.IP)
				return recvSrc != nil && recvSrc.Equal(sentDst)
			}
		}

		if recvICMP == nil {
			return false
		}
		typeVal, err := recvICMP.Get("type")
		if err != nil || typeVal == nil {
			return false
		}
		icmpType, _ := typeVal.(uint8)

		switch icmpType {
		case layers.ICMPv6EchoReply: // 129 — only meaningful for ICMPv6 probes
			if proto != ProtoICMP {
				return false
			}
			recvSrcVal, _ := recvIP.Get("src")
			recvSrc, _ := recvSrcVal.(net.IP)
			if recvSrc == nil || !recvSrc.Equal(sentDst) {
				return false
			}
			return echoIdentMatches(sent, received)

		case layers.ICMPv6DestUnreach, layers.ICMPv6TimeExceed: // 1 / 3
			return matchEmbedded(proto, sent, received, sentDst)
		}
		return false
	}
}

// echoIdentMatches reports whether an Echo Reply's id+seq match the sent probe.
func echoIdentMatches(sent, received *packet.Packet) bool {
	sentEcho := sent.GetLayer("ICMPv6 Echo")
	recvEcho := received.GetLayer("ICMPv6 Echo Reply")
	if sentEcho == nil || recvEcho == nil {
		return false
	}
	sIDVal, _ := sentEcho.Get("id")
	sSeqVal, _ := sentEcho.Get("seq")
	rIDVal, _ := recvEcho.Get("id")
	rSeqVal, _ := recvEcho.Get("seq")
	sID, _ := sIDVal.(uint16)
	sSeq, _ := sSeqVal.(uint16)
	rID, _ := rIDVal.(uint16)
	rSeq, _ := rSeqVal.(uint16)
	return sID == rID && sSeq == rSeq
}

// matchEmbedded confirms an ICMPv6 error message quotes our original probe by
// inspecting the embedded original IPv6+L4 header (carried in the Raw layer).
// The IPv6 header is a fixed 40 bytes (no IHL field); the inner destination
// address occupies bytes [24:40], and the upper-layer header follows at [40:].
func matchEmbedded(proto Protocol, sent, received *packet.Packet, sentDst net.IP) bool {
	raw := received.GetLayer("Raw")
	if raw == nil {
		return false
	}
	loadVal, err := raw.Get("load")
	if err != nil || loadVal == nil {
		return false
	}
	load, ok := loadVal.([]byte)
	if !ok {
		return false
	}
	// ICMPv6 error messages carry a 4-byte unused/MTU field before the quoted
	// invoking packet. goscapy leaves those bytes in the Raw load, so skip them
	// to reach the embedded original IPv6 header (fixed 40 bytes).
	if len(load) < 4+40 {
		return false
	}
	load = load[4:]

	innerDst := net.IP(load[24:40])
	if !innerDst.Equal(sentDst) {
		return false
	}

	inner := load[40:]
	switch proto {
	case ProtoICMP:
		// Inner ICMPv6 Echo: type[0],code[1],chksum[2:4],id[4:6],seq[6:8].
		if len(inner) < 8 {
			return true
		}
		sentEcho := sent.GetLayer("ICMPv6 Echo")
		if sentEcho == nil {
			return true
		}
		idVal, _ := sentEcho.Get("id")
		seqVal, _ := sentEcho.Get("seq")
		sentID, _ := idVal.(uint16)
		sentSeq, _ := seqVal.(uint16)
		innerID := uint16(inner[4])<<8 | uint16(inner[5])
		innerSeq := uint16(inner[6])<<8 | uint16(inner[7])
		return innerID == sentID && innerSeq == sentSeq

	case ProtoUDP, ProtoTCP:
		// Inner L4: sport at [0:2], dport at [2:4].
		if len(inner) < 4 {
			return true
		}
		l4 := "UDP"
		if proto == ProtoTCP {
			l4 = "TCP"
		}
		sentL4 := sent.GetLayer(l4)
		if sentL4 == nil {
			return true
		}
		spVal, _ := sentL4.Get("sport")
		dpVal, _ := sentL4.Get("dport")
		sentSport, _ := spVal.(uint16)
		sentDport, _ := dpVal.(uint16)
		innerSport := uint16(inner[0])<<8 | uint16(inner[1])
		innerDport := uint16(inner[2])<<8 | uint16(inner[3])
		return innerSport == sentSport && innerDport == sentDport
	}
	return true
}
