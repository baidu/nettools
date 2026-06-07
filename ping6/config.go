// Package ping6 implements multi-target ICMPv6 Echo Request probing for IPv6.
// It sends ICMPv6 Echo Request packets via raw sockets using the goscapy library,
// receives Echo Replies, and reports per-target latency and loss statistics.
package ping6

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Config holds all runtime parameters for the ICMPv6 ping tool.
type Config struct {
	TargetAddrs []string

	Rate         int64
	Span         time.Duration
	Delay        time.Duration
	Count        int
	SendDuration time.Duration

	Size    int
	TC      int // traffic class
	HopLimit int

	Timeout time.Duration

	LocalAddr string
	Interface string

	Verbose bool
	Hwts    bool
}

// Validate checks and fills in default values for the configuration.
// It auto-detects the local IPv6 address and interface when not explicitly provided.
func (c *Config) Validate() error {
	if len(c.TargetAddrs) == 0 {
		return fmt.Errorf("at least one target address is required")
	}
	for _, addr := range c.TargetAddrs {
		if err := validateIPv6(addr); err != nil {
			return err
		}
	}

	if c.LocalAddr == "" {
		ip, err := resolveLocalIPv6()
		if err != nil {
			return fmt.Errorf("local address not provided and failed to resolve local IPv6: %w", err)
		}
		c.LocalAddr = ip
	}
	if err := validateIPv6(c.LocalAddr); err != nil {
		return fmt.Errorf("invalid local IPv6 address: %w", err)
	}

	if c.Interface == "" {
		iface := findInterfaceByIPv6(c.LocalAddr)
		if iface == "" {
			return fmt.Errorf("cannot determine outgoing interface for %s, use --interface/-I", c.LocalAddr)
		}
		c.Interface = iface
	}

	if c.Rate == 0 {
		c.Rate = 100
	}
	if c.Span == 0 {
		c.Span = time.Second
	}
	if c.Delay == 0 {
		c.Delay = 3 * time.Second
	}
	if c.Size < 8 {
		c.Size = 64
	}
	if c.HopLimit == 0 {
		c.HopLimit = 64
	}
	if c.Timeout == 0 {
		c.Timeout = time.Second
	}

	return nil
}

// validateIPv6 checks that addr is a valid IPv6 address (not IPv4).
func validateIPv6(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid IPv6 address %q", addr)
	}
	if ip.To4() != nil {
		return fmt.Errorf("address %q is not an IPv6 address", addr)
	}
	return nil
}

// resolveLocalIPv6 returns the first non-loopback IPv6 address associated
// with the current hostname.
func resolveLocalIPv6() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %w", hostname, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() == nil && ip.To16() != nil && !ip.IsLoopback() {
			return addr, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no IPv6 address found for hostname %q", hostname)
}

// findInterfaceByIPv6 returns the interface name that has the given IPv6 address.
func findInterfaceByIPv6(ipStr string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(net.ParseIP(ipStr)) {
					return iface.Name
				}
			}
		}
	}
	return ""
}
