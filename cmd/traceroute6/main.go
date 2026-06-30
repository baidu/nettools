// Command traceroute6 performs hop-by-hop path probing (traceroute) for one or
// more IPv6 targets, using ICMPv6 Echo, UDP, or TCP SYN probes.
//
// It mirrors cmd/traceroute but operates over IPv6, using the Hop Limit field
// (the v6 analogue of TTL) and ICMPv6 error messages. All probe construction
// and reply parsing goes through smallnest/goscapy. Probes across hop limits
// and across targets are sent concurrently. Raw sockets require root /
// CAP_NET_RAW.
//
// Usage:
//
//	sudo traceroute6 [flags] <target1> [target2 ...]
//	sudo traceroute6 -p tcp --port 443 ipv6.google.com
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/baidu/nettools/traceroute/enrich"
	"github.com/baidu/nettools/traceroute6"
	"github.com/baidu/nettools/version"
	"github.com/spf13/pflag"
)

func main() {
	var (
		protocol     string
		maxHops      int
		queries      int
		port         uint16
		srcPort      uint16
		fixedDstPort bool
		srcIP        string
		dstIP        string
		timeout      time.Duration
		noDNS        bool
		trafficClass int
		parallel     int
		iface        string
		localAddr    string
		asn          bool
		geo          bool
		geoToken     string
	)

	pflag.StringVarP(&protocol, "protocol", "p", "icmp", "Probe protocol: icmp, udp or tcp")
	pflag.IntVarP(&maxHops, "max-hops", "m", 30, "Maximum number of hops (Hop Limit)")
	pflag.IntVarP(&queries, "queries", "q", 3, "Number of probes per hop")
	pflag.Uint16Var(&port, "port", 0, "Destination port for UDP/TCP (default 33434 for udp, 80 for tcp)")
	pflag.Uint16Var(&srcPort, "src-port", 0, "Source port for UDP/TCP probes (0 = per-probe auto)")
	pflag.BoolVar(&fixedDstPort, "fixed-dport", false, "Keep UDP destination port fixed at --port (do not increment per hop)")
	pflag.StringVar(&srcIP, "src-ip", "", "Override source IPv6 for UDP/TCP probes (spoofing; defaults to --local-addr)")
	pflag.StringVar(&dstIP, "dst-ip", "", "Override destination IPv6 written into UDP/TCP probes (defaults to target)")
	pflag.DurationVarP(&timeout, "timeout", "w", time.Second, "Per-probe timeout")
	pflag.BoolVar(&noDNS, "no-dns", false, "Disable reverse-DNS resolution of hop IPs")
	pflag.IntVarP(&trafficClass, "tos", "t", 0, "IPv6 Traffic Class value (v6 analogue of TOS/DSCP)")
	pflag.IntVar(&parallel, "parallel", 16, "Max concurrent in-flight probes")
	pflag.StringVarP(&iface, "interface", "I", "", "Outbound interface (auto-detected if empty)")
	pflag.StringVarP(&localAddr, "local-addr", "l", "", "Local source IPv6 address (auto-detected if empty)")
	pflag.BoolVar(&asn, "asn", false, "Annotate each hop with origin ASN/AS-name/BGP prefix via Team Cymru DNS (outbound DNS only)")
	pflag.BoolVar(&geo, "geo", false, "Annotate each hop with geo/ownership via ipinfo.io (sends hop IPs to a third party)")
	pflag.StringVar(&geoToken, "geo-token", "", "ipinfo.io API token for --geo (optional; anonymous tier used if empty)")

	showVersion := pflag.BoolP("version", "V", false, "Print version and exit")
	pflag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}

	proto, err := traceroute6.ParseProtocol(protocol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Default port depends on protocol when not explicitly set.
	if port == 0 {
		switch proto {
		case traceroute6.ProtoTCP:
			port = 80
		default:
			port = 33434
		}
	}

	var rawTargets []string
	for _, arg := range pflag.Args() {
		rawTargets = append(rawTargets, splitNonEmpty(arg)...)
	}
	if len(rawTargets) == 0 {
		fmt.Fprintf(os.Stderr, "error: at least one target is required\n")
		fmt.Fprintf(os.Stderr, "Usage: traceroute6 [flags] <target1> [target2 ...]\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	targets, err := resolveTargets(rawTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cfg := &traceroute6.Config{
		Targets:      targets,
		LocalAddr:    localAddr,
		Interface:    iface,
		Protocol:     proto,
		HopLimit:     maxHops,
		Queries:      queries,
		Port:         port,
		SrcPort:      srcPort,
		FixedDstPort: fixedDstPort,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		Timeout:      timeout,
		TrafficClass: trafficClass,
		Parallel:     parallel,
		ResolveDNS:   !noDNS,
	}
	if asn {
		cfg.Providers = append(cfg.Providers, enrich.NewCymruProvider())
	}
	if geo {
		cfg.Providers = append(cfg.Providers, enrich.NewIPInfoProvider(geoToken))
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	tracer := traceroute6.NewTracer(cfg)
	results, err := tracer.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute6 failed: %v\n", err)
		os.Exit(1)
	}

	for i, r := range results {
		if i > 0 {
			fmt.Println()
		}
		fmt.Print(r.String())
	}
}

// resolveTargets turns hostnames/IPs into IPv6 address strings. Each input may
// be a plain IPv6 literal, or a hostname resolved to its first AAAA address.
// IPv4-only inputs yield a clear error.
func resolveTargets(inputs []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	add := func(ip string) {
		if _, dup := seen[ip]; dup {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}

	for _, in := range inputs {
		if ip := net.ParseIP(in); ip != nil {
			if ip.To4() == nil && ip.To16() != nil {
				add(ip.String())
				continue
			}
			return nil, fmt.Errorf("not an IPv6 target (use traceroute for IPv4): %s", in)
		}
		addrs, err := net.LookupHost(in)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", in, err)
		}
		found := false
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil && ip.To16() != nil {
				add(ip.String())
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no IPv6 (AAAA) address for %q", in)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid IPv6 targets")
	}
	return out, nil
}

// splitNonEmpty splits a comma-separated string into trimmed, non-empty parts.
func splitNonEmpty(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
