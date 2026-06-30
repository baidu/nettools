package traceroute6

import (
	"fmt"
	"strings"
	"time"

	"github.com/baidu/nettools/traceroute/enrich"
)

// String renders the result in the classic traceroute layout: a header line
// followed by one line per hop. Each hop shows the responding host/IP and
// per-probe RTTs; ECMP (multiple responders at one Hop Limit) is shown inline.
// Unanswered probes render as "*".
func (r *Result) String() string {
	var b strings.Builder

	size := 60
	fmt.Fprintf(&b, "traceroute6 to %s (%s), %d hops max, %s probes, %d byte packets\n",
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
		for range h.Probes {
			b.WriteString("* ")
		}
		b.WriteByte('\n')
		return
	}

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
		fmt.Fprintf(b, "%s (%s)", label, addr.String())
		if ai < len(h.Infos) {
			if extra := formatInfo(h.Infos[ai]); extra != "" {
				b.WriteString(" ")
				b.WriteString(extra)
			}
		}
		b.WriteString(" ")
	}

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

// formatInfo renders enrichment metadata inline, e.g.
// "[AS15169 GOOGLE 2001:4860::/32 | US Mountain View]". Empty pieces are
// omitted; returns "" when no data is known.
func formatInfo(info *enrich.IPInfo) string {
	if info == nil {
		return ""
	}

	var asn []string
	if info.ASN != 0 {
		asn = append(asn, fmt.Sprintf("AS%d", info.ASN))
	}
	if info.ASName != "" {
		asn = append(asn, info.ASName)
	}
	if info.Prefix != "" {
		asn = append(asn, info.Prefix)
	}

	var geo []string
	for _, s := range []string{info.Country, info.Region, info.City} {
		if s != "" {
			geo = append(geo, s)
		}
	}
	if len(geo) == 0 && info.Org != "" && info.ASName == "" {
		geo = append(geo, info.Org)
	}

	var parts []string
	if len(asn) > 0 {
		parts = append(parts, strings.Join(asn, " "))
	}
	if len(geo) > 0 {
		parts = append(parts, strings.Join(geo, " "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, " | ") + "]"
}

// Summary returns a compact per-hop stat line: Hop Limit, responder,
// min/avg/max RTT and loss percentage. Useful for log-style output. The
// responder column is widened to fit IPv6 addresses.
func (r *Result) Summary() string {
	var b strings.Builder
	for i := range r.Hops {
		h := &r.Hops[i]
		addr := "*"
		if len(h.Addrs) > 0 {
			addr = h.Addrs[0].String()
		}
		fmt.Fprintf(&b, "ttl=%-3d %-39s loss=%.0f%% min=%s avg=%s max=%s\n",
			h.TTL, addr, h.LossRate()*100,
			formatRTT(h.MinRTT()), formatRTT(h.AvgRTT()), formatRTT(h.MaxRTT()))
	}
	return b.String()
}
