package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baidu/nettools/ping6"
	"github.com/baidu/nettools/version"
	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
)

func main() {
	var (
		targets      string
		localAddr    string
		iface        string
		tc           int
		hopLimit     int
		count        int
		sendDuration time.Duration
		delay        time.Duration
		timeout      time.Duration
		rate         int64
		size         int
		verbose      bool
		hwts         bool
		maxTargets   int
	)

	pflag.StringVarP(&targets, "targets", "T", "", "Comma-separated target IPv6 addresses or CIDR ranges")
	pflag.StringVarP(&localAddr, "local-addr", "l", "", "Local IPv6 address (auto-detected if empty)")
	pflag.StringVarP(&iface, "interface", "I", "", "Network interface (auto-detected if empty)")
	pflag.IntVarP(&tc, "tc", "", 0, "IPv6 traffic class (default: 0)")
	pflag.IntVarP(&hopLimit, "hlim", "", 64, "IPv6 hop limit (default: 64)")
	pflag.IntVarP(&count, "count", "c", 0, "Max packets to send per target (0 = unlimited)")
	pflag.DurationVarP(&sendDuration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.DurationVar(&delay, "delay", 3*time.Second, "Delay before processing stats")
	pflag.DurationVarP(&timeout, "timeout", "t", time.Second, "Socket read timeout")
	pflag.Int64VarP(&rate, "rate", "r", 100, "Packets per second per target")
	pflag.IntVarP(&size, "size", "s", 64, "ICMP payload size in bytes (min: 8)")
	pflag.BoolVar(&verbose, "verbose", false, "Print per-reply ICMP details")
	pflag.BoolVar(&hwts, "hwts", true, "Enable hardware timestamping (default: true)")
	pflag.IntVar(&maxTargets, "max-targets", 65536, "Max number of targets after CIDR/DNS expansion")

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
		fmt.Fprintf(os.Stderr, "Usage: mping6 [flags] <target1,target2,...>\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	// Expand CIDR ranges and resolve DNS hostnames.
	var resolvedAddrs []string
	for _, addr := range targetAddrs {
		// Try CIDR expansion first.
		if _, ipNet, err := net.ParseCIDR(addr); err == nil {
			expanded := expandCIDR6(ipNet)
			if len(expanded) > 0 {
				resolvedAddrs = append(resolvedAddrs, expanded...)
				continue
			}
		}
		// Try as plain IPv6 address.
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil && ip.To16() != nil {
			resolvedAddrs = append(resolvedAddrs, ip.String())
			continue
		}
		// Try DNS resolution (AAAA records).
		addrs, err := net.LookupHost(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot resolve %q: %v\n", addr, err)
			os.Exit(1)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil && ip.To16() != nil {
				resolvedAddrs = append(resolvedAddrs, a)
			}
		}
	}

	if len(resolvedAddrs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no valid IPv6 target addresses\n")
		os.Exit(1)
	}

	if len(resolvedAddrs) > maxTargets {
		fmt.Fprintf(os.Stderr, "warning: expanded to %d targets, capping at %d (--max-targets)\n", len(resolvedAddrs), maxTargets)
		resolvedAddrs = resolvedAddrs[:maxTargets]
	}

	cfg := &ping6.Config{
		TargetAddrs:  resolvedAddrs,
		Rate:         rate,
		Span:         time.Second,
		Delay:        delay,
		Count:        count,
		SendDuration: sendDuration,
		Size:         size,
		TC:           tc,
		HopLimit:     hopLimit,
		Timeout:      timeout,
		LocalAddr:    localAddr,
		Interface:    iface,
		Verbose:      verbose,
		Hwts:         hwts,
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
	p := ping6.NewPinger(cfg, limiter, logger)

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

// expandCIDR6 expands an IPv6 CIDR range into individual addresses.
// Only expands prefixes with 16 or fewer host bits (/112 - /128) to
// prevent excessive expansion.
func expandCIDR6(ipNet *net.IPNet) []string {
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil
	}

	hostBits := bits - ones
	if hostBits > 16 {
		// Too large — would produce more than 65536 addresses.
		return nil
	}

	numAddrs := 1 << hostBits
	addrs := make([]string, 0, numAddrs)

	base := ipNet.IP.To16()
	if base == nil {
		return nil
	}

	// Use big.Int for incrementing the 128-bit address.
	ipInt := new(big.Int).SetBytes(base)
	one := big.NewInt(1)

	for i := 0; i < numAddrs; i++ {
		addr := make(net.IP, 16)
		ipInt.FillBytes(addr)
		addrs = append(addrs, addr.String())
		ipInt.Add(ipInt, one)
	}

	return addrs
}
