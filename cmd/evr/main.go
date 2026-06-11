// Command evr is a VXLAN-based EVR probing tool.
//
// It sends UDP/VXLAN packets to one or more EVR VTEPs, where each probe
// carries an inner Ethernet/IPv4/UDP frame whose inner src/dst IPs both
// equal the local probing machine's address. The actual EVR src IP is
// embedded inside the payload so the EVR's reflection can be matched
// back to the originating target.
//
// Usage:
//
//	evr -c evr.json
//	evr --client-addr 10.0.0.1 --targets 10.0.1.10#192.168.100.1
//	evr -c evr.json --rate-in-span 5000   # CLI overrides config file
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/baidu/nettools/evr/agent"
	"github.com/baidu/nettools/evr/config"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"
	"github.com/baidu/nettools/version"
	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
)

// jsonConfig is the on-disk representation. Durations and port ranges
// are strings so the JSON file can use human-friendly values.
type jsonConfig struct {
	ID              string `json:"id"`
	ClientAddr      string `json:"client_addr"`
	Targets         string `json:"targets"`
	DstPort         uint16 `json:"dst_port"`
	InnerDstPort    uint16 `json:"inner_dst_port"`
	SrcMAC          string `json:"src_mac"`
	DstMAC          string `json:"dst_mac"`
	VNI             uint32 `json:"vni"`
	TOS             int    `json:"tos"`
	TTL             int    `json:"ttl"`
	ClientPortRange string `json:"client_port_range"`
	RateInSpan      int64  `json:"rate_in_span"`
	Span            string `json:"span"`
	Delay           string `json:"delay"`
	MsgLen          int    `json:"msg_len"`
	PprofAddr       string `json:"pprof_addr"`
	LogDir          string `json:"log_dir"`
	LogMaxAgeDays   int    `json:"log_max_age_days"`
	Verbose         bool   `json:"verbose"`
}

func main() {
	var (
		configFile      string
		id              string
		clientAddr      string
		targets         string
		dstPort         uint16
		innerDstPort    uint16
		srcMAC          string
		dstMAC          string
		vni             uint32
		tos             int
		ttl             int
		clientPortRange string
		rateInSpan      int64
		span            time.Duration
		delay           time.Duration
		msgLen          int
		pprofAddr       string
		logDir          string
		logMaxAgeDays   int
		verbose         bool
	)

	pflag.StringVarP(&configFile, "config", "c", "", "Path to JSON config file")
	pflag.StringVar(&id, "id", "", "Free-form agent identifier (used in logs)")
	pflag.StringVar(&clientAddr, "client-addr", "", "Local IPv4 used as the outer source (auto-detected if empty)")
	pflag.StringVarP(&targets, "targets", "t", "", "Comma-separated targets in vtep#evrSrc[#mockSrc] form")
	pflag.Uint16Var(&dstPort, "dst-port", 0, "Outer UDP destination port (default 4789)")
	pflag.Uint16Var(&innerDstPort, "inner-dst-port", 0, "Inner UDP destination port (default 8972)")
	pflag.StringVar(&srcMAC, "src-mac", "", "Inner Ethernet source MAC (default 00:00:00:00:ff:ff)")
	pflag.StringVar(&dstMAC, "dst-mac", "", "Inner Ethernet destination MAC (default 00:00:5e:00:01:ff)")
	pflag.Uint32Var(&vni, "vni", 0, "VXLAN Network Identifier (default 15990000)")
	pflag.IntVar(&tos, "tos", 0, "IPv4 TOS/DSCP value applied on both outer and inner IP layers")
	pflag.IntVar(&ttl, "ttl", 0, "IPv4 TTL applied on both outer and inner IP layers (default 64)")
	pflag.StringVar(&clientPortRange, "client-port-range", "", "Outer source UDP port range, e.g. 63000,63999 (default 9981,9981)")
	pflag.Int64Var(&rateInSpan, "rate-in-span", 0, "Probe packets per span across all targets (default 1)")
	pflag.DurationVarP(&span, "span", "s", 0, "Statistics reporting interval (default 100ms)")
	pflag.DurationVar(&delay, "delay", 0, "Delay before finalising a stats bucket (default 100ms)")
	pflag.IntVar(&msgLen, "msg-len", 0, "Inner UDP payload length in bytes (header + salt)")
	pflag.StringVar(&pprofAddr, "pprof", "", "Pprof listen address (e.g. :6060)")
	pflag.StringVar(&logDir, "log-dir", "", "Log directory for rotated log files")
	pflag.IntVar(&logMaxAgeDays, "log-max-age", 0, "Max days to keep log files (default 3)")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Print per-port loss details")

	showVersion := pflag.BoolP("version", "V", false, "Print version and exit")
	pflag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	defer func() {
		if err := recover(); err != nil {
			log.Printf("[FATAL] recovered: %v", err)
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, true)
			log.Printf("[FATAL] stack:\n%s", buf[:n])
			os.Exit(1)
		}
	}()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	var jc jsonConfig
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config %s: %v\n", configFile, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &jc); err != nil {
			fmt.Fprintf(os.Stderr, "parse config %s: %v\n", configFile, err)
			os.Exit(1)
		}
	}

	cfg, err := buildConfig(&jc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Override with explicitly set CLI flags. pflag.Visit only iterates
	// over flags the user actually passed, so the JSON file remains
	// authoritative for unset flags.
	var cliErr error
	pflag.Visit(func(f *pflag.Flag) {
		if cliErr != nil {
			return
		}
		switch f.Name {
		case "id":
			cfg.ID = id
		case "client-addr":
			cfg.ClientAddr = clientAddr
		case "targets":
			ts, err := config.ParseTargets(targets)
			if err != nil {
				cliErr = fmt.Errorf("--targets: %w", err)
				return
			}
			cfg.Targets = ts
		case "dst-port":
			cfg.DstPort = dstPort
		case "inner-dst-port":
			cfg.InnerDstPort = innerDstPort
		case "src-mac":
			cfg.SrcMAC = srcMAC
		case "dst-mac":
			cfg.DstMAC = dstMAC
		case "vni":
			cfg.VNI = vni
		case "tos":
			cfg.TOS = tos
		case "ttl":
			cfg.TTL = ttl
		case "client-port-range":
			pr, err := config.ParsePortRange(clientPortRange)
			if err != nil {
				cliErr = fmt.Errorf("--client-port-range: %w", err)
				return
			}
			cfg.ClientPortRange = pr
		case "rate-in-span":
			cfg.RateInSpan = rateInSpan
		case "span":
			cfg.Span = span
		case "delay":
			cfg.Delay = delay
		case "msg-len":
			cfg.MsgLen = msgLen
		case "pprof":
			cfg.PprofAddr = pprofAddr
		case "log-dir":
			cfg.LogDir = logDir
		case "log-max-age":
			cfg.LogMaxAgeDays = logMaxAgeDays
		case "verbose":
			cfg.Verbose = verbose
		}
	})
	if cliErr != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", cliErr)
		os.Exit(1)
	}

	if len(cfg.Targets) == 0 {
		fmt.Fprintln(os.Stderr, "error: --targets/-t or config file targets is required")
		pflag.Usage()
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	var logWriter *util.RotateWriter
	if cfg.LogDir != "" {
		maxAge := cfg.LogMaxAgeDays
		if maxAge <= 0 {
			maxAge = 7
		}
		w, err := util.NewRotateWriter(cfg.LogDir, "evr.log", maxAge)
		if err != nil {
			log.Fatalf("[FATAL] setup log: %v", err)
		}
		logWriter = w
		log.SetOutput(io.MultiWriter(os.Stderr, logWriter))
		defer func() { _ = logWriter.Close() }()
	}

	if cfg.PprofAddr != "" {
		go func() {
			log.Printf("[INFO] pprof on %s", cfg.PprofAddr)
			if err := http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
				log.Printf("[WARN] pprof: %v", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[INFO] signal %v, shutting down", sig)
		cancel()
	}()

	logger := log.Default()
	proc := stat.NewProcessor(cfg.Span, cfg.Delay)
	go proc.Run(ctx)

	limiter := ratelimit.New(int(cfg.RateInSpan), ratelimit.Per(cfg.Span))
	a := agent.New(cfg, limiter, proc, nil, logger)

	go func() {
		if err := a.Run(ctx); err != nil {
			log.Printf("[ERRO] agent: %v", err)
			cancel()
		}
	}()

	log.Printf("[INFO] evr agent %q started, %d targets", cfg.ID, len(cfg.Targets))

	<-ctx.Done()
	time.Sleep(1 * time.Second)
}

func buildConfig(jc *jsonConfig) (*config.Config, error) {
	cfg := &config.Config{
		ID:            jc.ID,
		ClientAddr:    jc.ClientAddr,
		DstPort:       jc.DstPort,
		InnerDstPort:  jc.InnerDstPort,
		SrcMAC:        jc.SrcMAC,
		DstMAC:        jc.DstMAC,
		VNI:           jc.VNI,
		TOS:           jc.TOS,
		TTL:           jc.TTL,
		RateInSpan:    jc.RateInSpan,
		MsgLen:        jc.MsgLen,
		PprofAddr:     jc.PprofAddr,
		LogDir:        jc.LogDir,
		LogMaxAgeDays: jc.LogMaxAgeDays,
		Verbose:       jc.Verbose,
	}

	if jc.Targets != "" {
		ts, err := config.ParseTargets(jc.Targets)
		if err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
		cfg.Targets = ts
	}

	if jc.ClientPortRange != "" {
		pr, err := config.ParsePortRange(jc.ClientPortRange)
		if err != nil {
			return nil, fmt.Errorf("client_port_range: %w", err)
		}
		cfg.ClientPortRange = pr
	}

	if jc.Span != "" {
		d, err := time.ParseDuration(jc.Span)
		if err != nil {
			return nil, fmt.Errorf("span: %w", err)
		}
		cfg.Span = d
	}
	if jc.Delay != "" {
		d, err := time.ParseDuration(jc.Delay)
		if err != nil {
			return nil, fmt.Errorf("delay: %w", err)
		}
		cfg.Delay = d
	}

	return cfg, nil
}
