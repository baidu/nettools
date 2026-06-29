// Package traceroute implements a hop-by-hop path probing tool (traceroute).
//
// It supports ICMP Echo, UDP, and TCP SYN probes. Every probe and reply is
// encoded/decoded with smallnest/goscapy layers — no hand-rolled byte/checksum
// logic. Probes across TTLs and across multiple targets run concurrently, with
// a configurable concurrency cap.
//
// Raw sockets require root / CAP_NET_RAW.
package traceroute

import (
	"fmt"
	"net"
	"time"
)

// Protocol selects the probe packet type.
type Protocol int

const (
	// ProtoICMP sends ICMP Echo Requests (default).
	ProtoICMP Protocol = iota
	// ProtoUDP sends UDP datagrams to an incrementing destination port.
	ProtoUDP
	// ProtoTCP sends TCP SYN segments to a fixed destination port.
	ProtoTCP
)

// String returns the upper-case protocol name (ICMP/UDP/TCP).
func (p Protocol) String() string {
	switch p {
	case ProtoUDP:
		return "UDP"
	case ProtoTCP:
		return "TCP"
	default:
		return "ICMP"
	}
}

// ParseProtocol parses a case-insensitive protocol name.
func ParseProtocol(s string) (Protocol, error) {
	switch s {
	case "icmp", "ICMP", "":
		return ProtoICMP, nil
	case "udp", "UDP":
		return ProtoUDP, nil
	case "tcp", "TCP":
		return ProtoTCP, nil
	default:
		return ProtoICMP, fmt.Errorf("unknown protocol %q (want icmp, udp or tcp)", s)
	}
}

// Config configures a traceroute run.
type Config struct {
	// Targets are the destination hosts (IPv4 addresses, resolved upstream).
	Targets []string

	// LocalAddr is the source IPv4 address; auto-detected if empty.
	LocalAddr string
	// Interface is the outbound NIC; auto-detected if empty.
	Interface string

	Protocol Protocol
	MaxHops  int           // maximum TTL to probe
	Queries  int           // probes per hop
	Port     uint16        // destination port for UDP/TCP (and base for UDP)
	Timeout  time.Duration // per-probe timeout
	TOS      int           // IP TOS/DSCP value

	// UDP/TCP source/destination overrides (ignored for ICMP).
	//
	// SrcPort fixes the probe source port. When 0, a per-(ttl,probe) port is
	// derived so concurrent probes stay distinguishable; setting it pins all
	// probes to one port (useful for firewall-rule testing, at the cost of
	// per-probe disambiguation on the source-port axis).
	SrcPort uint16
	// FixedDstPort, when true, keeps the destination port constant at Port for
	// UDP as well (the classic UDP traceroute otherwise increments dport per
	// TTL). TCP always uses a fixed Port.
	FixedDstPort bool
	// SrcIP overrides the source IP written into the probe (IP spoofing).
	// Empty means use the auto-detected / --local-addr source. Requires the
	// network path to permit the spoofed source.
	SrcIP string
	// DstIP overrides the destination IP written into the probe, independent
	// of the target label. Empty means probe the target itself.
	DstIP string

	// Parallel caps the number of in-flight probes (and concurrent targets).
	Parallel int

	// ResolveDNS enables reverse-DNS (PTR) lookups for each hop IP.
	ResolveDNS bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Protocol:   ProtoICMP,
		MaxHops:    30,
		Queries:    3,
		Port:       33434,
		Timeout:    time.Second,
		TOS:        0,
		Parallel:   16,
		ResolveDNS: true,
	}
}

// Validate checks the configuration for obvious errors.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	if c.MaxHops < 1 || c.MaxHops > 255 {
		return fmt.Errorf("max-hops must be in [1,255], got %d", c.MaxHops)
	}
	if c.Queries < 1 {
		return fmt.Errorf("queries must be >= 1, got %d", c.Queries)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0, got %s", c.Timeout)
	}
	if c.Parallel < 1 {
		return fmt.Errorf("parallel must be >= 1, got %d", c.Parallel)
	}
	if (c.Protocol == ProtoTCP || c.Protocol == ProtoUDP) && c.Port == 0 {
		return fmt.Errorf("port must be non-zero for %s probes", c.Protocol)
	}
	if c.SrcIP != "" {
		if ip := net.ParseIP(c.SrcIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid source IPv4 address: %q", c.SrcIP)
		}
	}
	if c.DstIP != "" {
		if ip := net.ParseIP(c.DstIP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid destination IPv4 address: %q", c.DstIP)
		}
	}
	if c.Protocol == ProtoICMP && (c.SrcPort != 0 || c.FixedDstPort) {
		return fmt.Errorf("--src-port/--fixed-dport only apply to udp/tcp probes")
	}
	return nil
}
