package traceroute

import (
	"fmt"
	"strings"
	"time"
)

// String renders the result in the classic traceroute layout (aeden/traceroute
// style): a header line followed by one line per hop. Each hop shows the
// responding host/IP and per-probe RTTs; ECMP (multiple responders at one TTL)
// is shown inline. Unanswered probes render as "*".
func (r *Result) String() string {
	var b strings.Builder

	size := 60
	fmt.Fprintf(&b, "traceroute to %s (%s), %d hops max, %s probes, %d byte packets\n",
		r.Dst, r.DstIP, r.MaxHops, r.Proto, size)

	for i := range r.Hops {
		writeHopLine(&b, &r.Hops[i])
	}
	return b.String()
}

// writeHopLine writes a single hop's line.
func writeHopLine(b *strings.Builder, h *Hop) {
	fmt.Fprintf(b, "%-3d ", h.TTL)

	if len(h.Addrs) == 0 {
		// No responder at all.
		for range h.Probes {
			b.WriteString("* ")
		}
		b.WriteByte('\n')
		return
	}

	// Print each distinct responder once with its host/IP, then the RTTs.
	for ai, addr := range h.Addrs {
		host := ""
		if ai < len(h.Hosts) {
			host = h.Hosts[ai]
		}
		label := addr.String()
		if host != "" {
			label = strings.TrimSuffix(host, ".")
		}
		if ai > 0 {
			b.WriteString("    ") // align continuation responders
		}
		fmt.Fprintf(b, "%s (%s) ", label, addr.String())
	}

	// RTTs: one entry per probe, "*" for timeouts.
	for _, p := range h.Probes {
		if p.TimedOut {
			b.WriteString(" *")
		} else {
			fmt.Fprintf(b, "  %s", formatRTT(p.RTT))
		}
	}
	b.WriteByte('\n')
}

// formatRTT formats a duration as milliseconds with 3 decimals, e.g. "1.234ms".
func formatRTT(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
}

// Summary returns a compact per-hop stat line: TTL, responder, min/avg/max RTT
// and loss percentage. Useful for log-style output.
func (r *Result) Summary() string {
	var b strings.Builder
	for i := range r.Hops {
		h := &r.Hops[i]
		addr := "*"
		if len(h.Addrs) > 0 {
			addr = h.Addrs[0].String()
		}
		fmt.Fprintf(&b, "ttl=%-3d %-15s loss=%.0f%% min=%s avg=%s max=%s\n",
			h.TTL, addr, h.LossRate()*100,
			formatRTT(h.MinRTT()), formatRTT(h.AvgRTT()), formatRTT(h.MaxRTT()))
	}
	return b.String()
}
