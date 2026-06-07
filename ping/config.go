// Package ping implements multi-target ICMP Echo Request probing for IPv4.
// It sends ICMP Echo Request packets via raw sockets using the goscapy library,
// receives Echo Replies, and reports per-target latency and loss statistics.
package ping

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Config holds all runtime parameters for the ICMP ping tool.
type Config struct {
	TargetAddrs []string

	Rate         int64
	Span         time.Duration
	Delay        time.Duration
	Count        int
	SendDuration time.Duration

	Size    int
	TOS     int
	TTL     int
	Timeout time.Duration

	LocalAddr string
	Interface string

	Verbose bool
}

// Validate checks and fills in default values for the configuration.
// It auto-detects the local IP address and interface when not explicitly provided.
func (c *Config) Validate() error {
	if len(c.TargetAddrs) == 0 {
		return fmt.Errorf("at least one target address is required")
	}
	for _, addr := range c.TargetAddrs {
		if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid target IPv4 address: %q", addr)
		}
	}

	if c.LocalAddr == "" {
		ip, err := resolveLocalIP()
		if err != nil {
			return fmt.Errorf("local address not provided and failed to resolve local IP: %w", err)
		}
		c.LocalAddr = ip
	}
	if ip := net.ParseIP(c.LocalAddr); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid local IPv4 address: %q", c.LocalAddr)
	}

	if c.Interface == "" {
		iface := findInterfaceByIP(c.LocalAddr)
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
	if c.TTL == 0 {
		c.TTL = 64
	}
	if c.Timeout == 0 {
		c.Timeout = time.Second
	}

	return nil
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
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return addr, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no address found for hostname %q", hostname)
}

// findInterfaceByIP returns the interface name that has the given IP address.
func findInterfaceByIP(ipStr string) string {
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
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ipStr {
				return iface.Name
			}
		}
	}
	return ""
}
