package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baidu/nettools/ping"
	"github.com/baidu/nettools/version"
	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
)

func main() {
	var (
		targets      string
		localAddr    string
		iface        string
		tos          int
		ttl          int
		count        int
		sendDuration time.Duration
		delay        time.Duration
		timeout      time.Duration
		rate         int64
		size         int
		verbose      bool
	)

	pflag.StringVarP(&targets, "targets", "T", "", "Comma-separated target IPv4 addresses or CIDR ranges")
	pflag.StringVarP(&localAddr, "local-addr", "l", "", "Local IP address (auto-detected if empty)")
	pflag.StringVarP(&iface, "interface", "I", "", "Network interface (auto-detected if empty)")
	pflag.IntVarP(&tos, "tos", "z", 0, "IP TOS/DSCP value (default: 0)")
	pflag.IntVarP(&ttl, "ttl", "", 64, "IP TTL (default: 64)")
	pflag.IntVarP(&count, "count", "c", 0, "Max packets to send per target (0 = unlimited)")
	pflag.DurationVarP(&sendDuration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.DurationVar(&delay, "delay", 3*time.Second, "Delay before processing stats")
	pflag.DurationVarP(&timeout, "timeout", "t", time.Second, "Socket read timeout")
	pflag.Int64VarP(&rate, "rate", "r", 100, "Packets per second per target")
	pflag.IntVarP(&size, "size", "s", 64, "ICMP payload size in bytes (min: 8)")
	pflag.BoolVar(&verbose, "verbose", false, "Print per-reply ICMP details")

	showVersion := pflag.BoolP("version", "V", false, "Print version and exit")
	pflag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Collect targets from positional args or --targets flag.
	var targetAddrs []string
	if targets != "" {
		targetAddrs = splitNonEmpty(targets)
	}
	// Also accept positional arguments.
	for _, arg := range pflag.Args() {
		targetAddrs = append(targetAddrs, splitNonEmpty(arg)...)
	}

	if len(targetAddrs) == 0 {
		fmt.Fprintf(os.Stderr, "error: at least one target address is required\n")
		fmt.Fprintf(os.Stderr, "Usage: mping [flags] <target1,target2,...>\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	// Expand CIDR ranges and resolve DNS hostnames.
	var resolvedAddrs []string
	for _, addr := range targetAddrs {
		// Try CIDR expansion first.
		if _, ipNet, err := net.ParseCIDR(addr); err == nil {
			expanded := expandCIDR(ipNet)
			if len(expanded) > 0 {
				resolvedAddrs = append(resolvedAddrs, expanded...)
				continue
			}
		}
		// Try as plain IP.
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			resolvedAddrs = append(resolvedAddrs, ip.String())
			continue
		}
		// Try DNS resolution.
		addrs, err := net.LookupHost(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot resolve %q: %v\n", addr, err)
			os.Exit(1)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				resolvedAddrs = append(resolvedAddrs, a)
			}
		}
	}

	if len(resolvedAddrs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no valid IPv4 target addresses\n")
		os.Exit(1)
	}

	cfg := &ping.Config{
		TargetAddrs:  resolvedAddrs,
		Rate:         rate,
		Span:         time.Second,
		Delay:        delay,
		Count:        count,
		SendDuration: sendDuration,
		Size:         size,
		TOS:          tos,
		TTL:          ttl,
		Timeout:      timeout,
		LocalAddr:    localAddr,
		Interface:    iface,
		Verbose:      verbose,
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := log.Default()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[INFO] received signal, shutting down...")
		cancel()
	}()

	limiter := ratelimit.New(int(cfg.Rate), ratelimit.Per(cfg.Span))
	p := ping.NewPinger(cfg, limiter, logger)

	if err := p.Run(ctx); err != nil {
		log.Printf("[ERRO] pinger error: %v", err)
		os.Exit(1)
	}
}

// splitNonEmpty splits a comma-separated string into trimmed, non-empty parts.
func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// expandCIDR expands a CIDR range into individual IPv4 addresses,
// excluding the network and broadcast addresses.
func expandCIDR(ipNet *net.IPNet) []string {
	var addrs []string
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipNet.Mask
	if len(mask) != 4 {
		return nil
	}

	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = network[i] | ^mask[i]
	}

	current := make(net.IP, 4)
	copy(current, network)
	for {
		current = incrementIP(current)
		if current.Equal(broadcast) || current.Equal(network) {
			break
		}
		addrs = append(addrs, current.String())
	}
	return addrs
}

// incrementIP increments an IPv4 address by 1.
func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)
	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			break
		}
	}
	return result
}
