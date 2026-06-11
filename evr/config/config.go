// Package config defines the runtime configuration for the EVR VXLAN
// probing tool. The probe targets one or more EVR VTEPs; each target is
// expressed as "vtepIP#evrSrcIP" or "vtepIP#evrSrcIP#mockSrcIP".
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/baidu/nettools/stat"
)

// PortRange is an alias for stat.PortRange.
type PortRange = stat.PortRange

// Target identifies one EVR endpoint to probe.
type Target struct {
	// VTEPAddr is the outer destination IP (the VTEP).
	VTEPAddr string
	// EVRSrcAddr is the inner source IP carried by the inner Ethernet/IPv4
	// frame; it is also embedded in the payload so the response can be
	// matched back to the original target.
	EVRSrcAddr string
	// MockSrcAddr is an optional spoofed outer source IP. Empty means use
	// the local client address.
	MockSrcAddr string
}

// String renders a Target back into its config format.
func (t Target) String() string {
	if t.MockSrcAddr != "" {
		return t.VTEPAddr + "#" + t.EVRSrcAddr + "#" + t.MockSrcAddr
	}
	return t.VTEPAddr + "#" + t.EVRSrcAddr
}

// ParseTarget parses a "vtep#evr[#mock]" specification into a Target.
func ParseTarget(s string) (Target, error) {
	items := strings.Split(strings.TrimSpace(s), "#")
	switch len(items) {
	case 2:
		if items[0] == "" || items[1] == "" {
			return Target{}, fmt.Errorf("invalid target %q", s)
		}
		return Target{VTEPAddr: items[0], EVRSrcAddr: items[1]}, nil
	case 3:
		if items[0] == "" || items[1] == "" {
			return Target{}, fmt.Errorf("invalid target %q", s)
		}
		return Target{VTEPAddr: items[0], EVRSrcAddr: items[1], MockSrcAddr: items[2]}, nil
	default:
		return Target{}, fmt.Errorf("invalid target %q: expected vtep#evr[#mock]", s)
	}
}

// ParseTargets parses a comma-separated list of targets.
func ParseTargets(s string) ([]Target, error) {
	if s == "" {
		return nil, errors.New("targets is empty")
	}
	var out []Target
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		t, err := ParseTarget(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("targets is empty")
	}
	return out, nil
}

// ParsePortRange parses a "min,max" string into a PortRange.
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return PortRange{}, fmt.Errorf("invalid port range %q: expected min,max", s)
	}
	portMin, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid min port in %q: %w", s, err)
	}
	portMax, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid max port in %q: %w", s, err)
	}
	if portMin > portMax {
		return PortRange{}, fmt.Errorf("invalid port range %q: min > max", s)
	}
	if portMin < 1 || portMax > 65535 {
		return PortRange{}, fmt.Errorf("invalid port range %q: ports must be between 1 and 65535", s)
	}
	return PortRange{Min: portMin, Max: portMax}, nil
}

// Config holds all runtime parameters for the EVR probing agent.
type Config struct {
	// ID identifies this agent (free-form, used for logging).
	ID string
	// ClientAddr is the local IPv4 address used as the outer source.
	ClientAddr string
	// Targets is the list of EVR endpoints to probe.
	Targets []Target

	// DstPort is the outer UDP destination port (VXLAN, default 4789).
	DstPort uint16
	// InnerDstPort is the inner UDP destination port that the EVR will
	// reflect back. Default 8972.
	InnerDstPort uint16
	// SrcMAC is the inner Ethernet source MAC.
	SrcMAC string
	// DstMAC is the inner Ethernet destination MAC.
	DstMAC string
	// VNI is the VXLAN Network Identifier.
	VNI uint32

	// TOS is the IPv4 type-of-service value applied on both outer and
	// inner IP layers.
	TOS int
	// TTL is the IPv4 time-to-live used on both layers.
	TTL int

	// ClientPortRange is the outer source UDP port range.
	ClientPortRange PortRange
	// RateInSpan is the number of probe packets sent per Span across all
	// targets combined.
	RateInSpan int64
	// Span is the statistics reporting interval.
	Span time.Duration
	// Delay is how long the stats processor lags real time before
	// finalising a bucket.
	Delay time.Duration
	// MsgLen is the length of the inner UDP payload (header + salt).
	MsgLen int

	// PprofAddr is the listen address for net/http/pprof. Empty disables it.
	PprofAddr string
	// LogDir is the directory for rotated log files. Empty logs to stderr.
	LogDir string
	// LogMaxAgeDays is how many days of rotated logs to keep.
	LogMaxAgeDays int
	// Verbose, when true, asks the LogSender to include per-port loss details.
	Verbose bool
}

// resolveLocalIP returns the first non-loopback IPv4 address associated
// with the current hostname.
func resolveLocalIP() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %w", hostname, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && !ip.IsLoopback() && ip.To4() != nil {
			return addr, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no address found for hostname %q", hostname)
}

// Validate checks the configuration and fills in defaults.
func (c *Config) Validate() error {
	if c.ClientAddr == "" {
		addr, err := resolveLocalIP()
		if err != nil {
			return fmt.Errorf("client_addr is empty and auto-detect failed: %w", err)
		}
		c.ClientAddr = addr
	}
	if ip := net.ParseIP(c.ClientAddr); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid client_addr %q: must be IPv4", c.ClientAddr)
	}

	if len(c.Targets) == 0 {
		return errors.New("targets must not be empty")
	}
	for _, t := range c.Targets {
		if ip := net.ParseIP(t.VTEPAddr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid target vtep %q: must be IPv4", t.VTEPAddr)
		}
		if ip := net.ParseIP(t.EVRSrcAddr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid target evr_src %q: must be IPv4", t.EVRSrcAddr)
		}
		if t.MockSrcAddr != "" {
			if ip := net.ParseIP(t.MockSrcAddr); ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid target mock_src %q: must be IPv4", t.MockSrcAddr)
			}
		}
	}

	if c.DstPort == 0 {
		c.DstPort = 4789
	}
	if c.InnerDstPort == 0 {
		c.InnerDstPort = 8972
	}
	if c.SrcMAC == "" {
		c.SrcMAC = "00:00:00:00:ff:ff"
	}
	if c.DstMAC == "" {
		c.DstMAC = "00:00:5e:00:01:ff"
	}
	if _, err := net.ParseMAC(c.SrcMAC); err != nil {
		return fmt.Errorf("invalid src_mac %q: %w", c.SrcMAC, err)
	}
	if _, err := net.ParseMAC(c.DstMAC); err != nil {
		return fmt.Errorf("invalid dst_mac %q: %w", c.DstMAC, err)
	}
	if c.VNI == 0 {
		c.VNI = 15990000
	}
	if c.VNI > 0xFFFFFF {
		return fmt.Errorf("invalid vni %d: must fit in 24 bits", c.VNI)
	}
	if c.TTL == 0 {
		c.TTL = 64
	}

	if c.ClientPortRange == (PortRange{}) {
		c.ClientPortRange = PortRange{Min: 9981, Max: 9981}
	}
	if c.ClientPortRange.Min < 1 || c.ClientPortRange.Max > 65535 || c.ClientPortRange.Min > c.ClientPortRange.Max {
		return fmt.Errorf("invalid client_port_range %v", c.ClientPortRange)
	}

	if c.RateInSpan <= 0 {
		c.RateInSpan = 1
	}
	if c.Span <= 0 {
		c.Span = 100 * time.Millisecond
	}
	if c.Delay <= 0 {
		c.Delay = 100 * time.Millisecond
	}
	if c.MsgLen <= 0 {
		return errors.New("msg_len must be positive")
	}
	if c.LogMaxAgeDays <= 0 {
		c.LogMaxAgeDays = 3
	}
	return nil
}

// GetNextPort advances a single port within the given inclusive range.
func GetNextPort(port uint16, pr PortRange) uint16 {
	port++
	if port > uint16(pr.Max) || port < uint16(pr.Min) {
		port = uint16(pr.Min)
	}
	return port
}
