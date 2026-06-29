package traceroute

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Tracer runs traceroute probes for one or more targets.
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

	// Bound concurrent in-flight probes across all targets/hops.
	sem := make(chan struct{}, t.conf.Parallel)

	var targetWG sync.WaitGroup
	for ti, dst := range t.conf.Targets {
		dstIP := net.ParseIP(dst).To4()
		if dstIP == nil {
			results[ti] = &Result{Dst: dst, Proto: t.conf.Protocol, MaxHops: t.conf.MaxHops}
			continue
		}

		// The actual probe destination may be overridden (independent of the
		// label) for UDP/TCP testing of specific forwarding paths.
		probeDst := dstIP
		if t.conf.DstIP != "" {
			if ip := net.ParseIP(t.conf.DstIP).To4(); ip != nil {
				probeDst = ip
			} else {
				return nil, fmt.Errorf("invalid destination IPv4 address: %q", t.conf.DstIP)
			}
		}

		srcIP, iface, err := localEndpoint(t.conf, probeDst)
		if err != nil {
			return nil, err
		}
		// Honor an explicit source-IP override (spoofing).
		if t.conf.SrcIP != "" {
			if ip := net.ParseIP(t.conf.SrcIP).To4(); ip != nil {
				srcIP = ip
			} else {
				return nil, fmt.Errorf("invalid source IPv4 address: %q", t.conf.SrcIP)
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
	return results, nil
}

// traceTarget probes every TTL for a single destination. All TTLs (and the
// probes within each) are sent concurrently, capped by sem; replies are matched
// back to their probe by goscapy's Sr1 matcher. probeDst is the IP actually
// written into probes (may differ from the displayed dstIP when --dst-ip is set).
func (t *Tracer) traceTarget(dst string, dstIP, probeDst, srcIP net.IP, iface string, sem chan struct{}) *Result {
	res := &Result{
		Dst:     dst,
		DstIP:   dstIP,
		Proto:   t.conf.Protocol,
		MaxHops: t.conf.MaxHops,
		Hops:    make([]Hop, t.conf.MaxHops),
	}

	var wg sync.WaitGroup
	for ttl := 1; ttl <= t.conf.MaxHops; ttl++ {
		res.Hops[ttl-1].TTL = ttl
		for probe := 0; probe < t.conf.Queries; probe++ {
			wg.Add(1)
			go func(ttl, probe int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				pr := t.sendProbe(srcIP, probeDst, iface, ttl, probe)

				// Append result; per-hop slice element is fixed, but Probes
				// is appended concurrently across probes of the same TTL.
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

// sendProbe builds, sends, and awaits a single probe at the given TTL.
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
//   - ICMP: id=pid, seq encodes ttl/probe
//   - UDP/TCP: source port encodes pid+probe, dest port identifies the flow
func (t *Tracer) buildProbe(srcIP, dstIP net.IP, ttl, probe int) *packet.Packet {
	ip := layers.NewIP()
	_ = ip.Set("src", srcIP)
	_ = ip.Set("dst", dstIP)
	_ = ip.Set("ttl", uint8(ttl))
	if t.conf.TOS != 0 {
		_ = ip.Set("tos", uint8(t.conf.TOS))
	}

	switch t.conf.Protocol {
	case ProtoUDP:
		_ = ip.Set("proto", layers.IPProtoUDP)
		udp := layers.NewUDP()
		_ = udp.Set("sport", t.udpSrcPort(ttl, probe))
		_ = udp.Set("dport", t.dstPort(ttl))
		pkt := ip.Over(udp)
		raw := layers.NewRaw()
		_ = raw.Set("load", probePayload(ttl, probe))
		pkt.Push(raw)
		return pkt

	case ProtoTCP:
		_ = ip.Set("proto", layers.IPProtoTCP)
		tcp := layers.NewTCP()
		// Encode ttl+probe into the source port so concurrent probes are
		// distinguishable in the quoted header of ICMP Time Exceeded replies
		// (the destination port is fixed for TCP traceroute), unless the user
		// pinned an explicit source port.
		_ = tcp.Set("sport", t.tcpSrcPort(ttl, probe))
		_ = tcp.Set("dport", t.conf.Port)
		_ = tcp.Set("flags", layers.TCPSyn)
		_ = tcp.Set("seq", uint32(ttl)<<16|uint32(probe))
		return ip.Over(tcp)

	default: // ProtoICMP
		_ = ip.Set("proto", layers.IPProtoICMP)
		icmp := layers.NewICMPEcho(t.pid, uint16(ttl)<<8|uint16(probe&0xFF))
		return ip.Over(icmp)
	}
}

// dstPort returns the destination port for a UDP probe. The classic UDP
// traceroute increments the port per TTL; FixedDstPort pins it to Port.
func (t *Tracer) dstPort(ttl int) uint16 {
	if t.conf.FixedDstPort {
		return t.conf.Port
	}
	return t.conf.Port + uint16(ttl)
}

// udpSrcPort returns the UDP source port: the user's fixed SrcPort if set,
// otherwise a per-(ttl,probe) value (kept above the well-known range, like the
// TCP path) for concurrent disambiguation.
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
// so concurrent UDP/TCP probes can be told apart in quoted ICMP error headers.
// Kept in the 33000+ range to avoid clashing with well-known ports.
func ephemeralSrcPort(pid uint16, ttl, probe int) uint16 {
	return 33000 + (pid+uint16(ttl)*16+uint16(probe))%30000
}

// buildMatcher returns a goscapy MatchFunc that pairs a reply with the sent
// probe. It accepts ICMP Time Exceeded / Destination Unreachable carrying our
// original packet, plus direct replies (Echo Reply, TCP SYN-ACK/RST) from the
// destination. All parsing of the embedded original packet uses goscapy layers.
func buildMatcher(proto Protocol, dstIP net.IP) sendrecv.MatchFunc {
	return func(sent, received *packet.Packet) bool {
		recvIP := received.GetLayer("IP")
		if recvIP == nil {
			return false
		}
		sentIP := sent.GetLayer("IP")
		if sentIP == nil {
			return false
		}
		sentDstVal, _ := sentIP.Get("dst")
		sentDst, _ := sentDstVal.(net.IP)
		if sentDst == nil {
			return false
		}

		recvICMP := received.GetLayer("ICMP")

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
		case 0: // Echo Reply — only meaningful for ICMP probes
			if proto != ProtoICMP {
				return false
			}
			recvSrcVal, _ := recvIP.Get("src")
			recvSrc, _ := recvSrcVal.(net.IP)
			if recvSrc == nil || !recvSrc.Equal(sentDst) {
				return false
			}
			// The destination echoes our id+seq back. Concurrent probes share
			// the wire (each Sr1 opens its own promiscuous receiver), so we
			// MUST confirm the echoed id+seq match this probe — otherwise a
			// single Echo Reply from the destination would match every
			// in-flight probe and be misattributed to a low TTL.
			return echoIdentMatches(sent, recvICMP)

		case 3, 11: // Destination Unreachable / Time Exceeded
			return matchEmbedded(proto, sent, received, sentDst)
		}
		return false
	}
}

// echoIdentMatches reports whether an Echo Reply's id+seq match the sent probe.
func echoIdentMatches(sent *packet.Packet, recvICMP *packet.Layer) bool {
	sentICMP := sent.GetLayer("ICMP")
	if sentICMP == nil {
		return false
	}
	sIDVal, _ := sentICMP.Get("id")
	sSeqVal, _ := sentICMP.Get("seq")
	rIDVal, _ := recvICMP.Get("id")
	rSeqVal, _ := recvICMP.Get("seq")
	sID, _ := sIDVal.(uint16)
	sSeq, _ := sSeqVal.(uint16)
	rID, _ := rIDVal.(uint16)
	rSeq, _ := rSeqVal.(uint16)
	return sID == rID && sSeq == rSeq
}

// matchEmbedded confirms an ICMP error message quotes our original probe by
// inspecting the embedded original IP+L4 header (carried in the Raw layer).
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
	if !ok || len(load) < 20 {
		return false
	}

	// Inner IP header: bytes [16:20] hold the original destination.
	ihl := int(load[0]&0x0F) * 4
	if ihl < 20 || len(load) < ihl {
		ihl = 20
	}
	innerDst := net.IP(load[16:20])
	if !innerDst.Equal(sentDst) {
		return false
	}

	// Match the L4 identifier we embedded in the original probe.
	inner := load[ihl:]
	switch proto {
	case ProtoICMP:
		// Inner ICMP: id at [4:6], seq at [6:8]. Compare against sent.
		if len(inner) < 8 {
			return true // dst already matched; accept
		}
		sentICMP := sent.GetLayer("ICMP")
		if sentICMP == nil {
			return true
		}
		idVal, _ := sentICMP.Get("id")
		seqVal, _ := sentICMP.Get("seq")
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
