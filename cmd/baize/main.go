package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/baidu/nettools/sonar/client"
	"github.com/baidu/nettools/sonar/config"
	"github.com/baidu/nettools/sonar/server"
	"github.com/baidu/nettools/stat"
	"go.uber.org/ratelimit"
)

type clientConfig struct {
	ClientAddr      string `json:"client_addr"`
	ServerAddrs     string `json:"server_addrs"`
	TOS             int    `json:"tos"`
	ClientPortRange string `json:"client_port_range"`
	ServerPortRange string `json:"server_port_range"`
	RateInSpan      int64  `json:"rate_in_span"`
	Span            string `json:"span"`
	Delay           string `json:"delay"`
	MsgLen          int    `json:"msg_len"`
	Count           int    `json:"count"`
	SendDuration    string `json:"send_duration"`
	Verbose         bool   `json:"verbose"`
}

type serverConfig struct {
	ServerAddr      string `json:"server_addr"`
	ClientAddrs     string `json:"client_addrs"`
	TOS             int    `json:"tos"`
	ClientPortRange string `json:"client_port_range"`
	ServerPortRange string `json:"server_port_range"`
	RateInSpan      int64  `json:"rate_in_span"`
	Span            string `json:"span"`
	Delay           string `json:"delay"`
	MsgLen          int    `json:"msg_len"`
	Verbose         bool   `json:"verbose"`
}

type baizeConfig struct {
	PprofAddr     string        `json:"pprof_addr"`
	LogDir        string        `json:"log_dir"`
	LogMaxAgeDays int           `json:"log_max_age_days"`
	Client        *clientConfig `json:"client"`
	Server        *serverConfig `json:"server"`
}

var configFile = flag.String("c", "baize.json", "path to config file")

func main() {
	flag.Parse()

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

	data, err := os.ReadFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config %s: %v\n", *configFile, err)
		os.Exit(1)
	}

	var cfg baizeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(1)
	}

	if cfg.Client == nil && cfg.Server == nil {
		fmt.Fprintln(os.Stderr, "no client or server config")
		os.Exit(1)
	}

	var logWriter *rotateWriter
	if cfg.LogDir != "" {
		logWriter = setupLog(cfg.LogDir, cfg.LogMaxAgeDays)
		defer logWriter.Close()
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

	if cfg.Client != nil {
		go runClient(ctx, cancel, cfg.Client)
	}
	if cfg.Server != nil {
		go runServer(ctx, cancel, cfg.Server)
	}

	<-ctx.Done()
	time.Sleep(1 * time.Second)
}

func runClient(ctx context.Context, cancel context.CancelFunc, cfg *clientConfig) {
	cpr, err := parsePortRange(cfg.ClientPortRange)
	if err != nil {
		log.Printf("[ERRO] client port range: %v", err)
		cancel()
		return
	}
	spr, err := parsePortRange(cfg.ServerPortRange)
	if err != nil {
		log.Printf("[ERRO] server port range: %v", err)
		cancel()
		return
	}

	conf := &config.Config{
		Role:            config.RoleClient,
		ClientAddr:      cfg.ClientAddr,
		ClientAddrs:     splitNonEmpty(cfg.ClientAddr),
		ServerAddrs:     splitNonEmpty(cfg.ServerAddrs),
		TOS:             cfg.TOS,
		ClientPortRange: cpr,
		ServerPortRange: spr,
		RateInSpan:      cfg.RateInSpan,
		Span:            parseDuration(cfg.Span),
		Delay:           parseDuration(cfg.Delay),
		MsgLen:          cfg.MsgLen,
		Count:           cfg.Count,
		SendDuration:    parseDuration(cfg.SendDuration),
		Verbose:         cfg.Verbose,
	}

	if err := conf.Validate(); err != nil {
		log.Printf("[ERRO] client config: %v", err)
		cancel()
		return
	}

	logger := log.Default()
	proc := stat.NewProcessor(conf.Span, conf.Delay)
	go proc.Run(ctx)

	limiter := ratelimit.New(int(conf.RateInSpan), ratelimit.Per(conf.Span))
	c := client.NewClient(conf, limiter, proc, nil, logger)
	c.ExitOnReachLimit = false

	go func() {
		if err := c.Run(ctx); err != nil {
			log.Printf("[ERRO] client: %v", err)
		}
	}()

	log.Printf("[INFO] client %s -> %v", conf.ClientAddr, conf.ServerAddrs)
	<-ctx.Done()
}

func runServer(ctx context.Context, cancel context.CancelFunc, cfg *serverConfig) {
	cpr, err := parsePortRange(cfg.ClientPortRange)
	if err != nil {
		log.Printf("[ERRO] client port range: %v", err)
		cancel()
		return
	}
	spr, err := parsePortRange(cfg.ServerPortRange)
	if err != nil {
		log.Printf("[ERRO] server port range: %v", err)
		cancel()
		return
	}

	conf := &config.Config{
		Role:            config.RoleServer,
		ClientAddrs:     splitNonEmpty(cfg.ClientAddrs),
		ServerAddrs:     []string{cfg.ServerAddr},
		TOS:             cfg.TOS,
		ClientPortRange: cpr,
		ServerPortRange: spr,
		RateInSpan:      cfg.RateInSpan,
		Span:            parseDuration(cfg.Span),
		Delay:           parseDuration(cfg.Delay),
		MsgLen:          cfg.MsgLen,
		Verbose:         cfg.Verbose,
	}

	if err := conf.Validate(); err != nil {
		log.Printf("[ERRO] server config: %v", err)
		cancel()
		return
	}

	logger := log.Default()
	proc := stat.NewProcessor(conf.Span, conf.Delay)
	go proc.Run(ctx)

	s := server.New(conf, proc, nil, logger)
	log.Printf("[INFO] server %s for clients %v", conf.ServerAddr(), conf.ClientAddrs)
	s.Run(ctx)
}

// rotateWriter writes to date-stamped log files with daily rotation
// and a symlink pointing to the current file.
type rotateWriter struct {
	dir    string
	maxAge int
	mu     sync.Mutex
	file   *os.File
	date   string
}

func (w *rotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().Format("20060102")
	if today != w.date {
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
		}
		name := "baize.log." + today
		f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			w.date = ""
			return 0, fmt.Errorf("open log file: %w", err)
		}
		w.file = f
		w.date = today
		link := filepath.Join(w.dir, "baize.log")
		_ = os.Remove(link)
		_ = os.Symlink(name, link)
		w.clean()
	}
	if w.file == nil {
		return 0, fmt.Errorf("log file not open")
	}
	return w.file.Write(p)
}

func (w *rotateWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
	}
}

func (w *rotateWriter) clean() {
	if w.maxAge <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -w.maxAge)
	entries, _ := os.ReadDir(w.dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "baize.log.") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(w.dir, e.Name()))
	}
}

func setupLog(dir string, maxAgeDays int) *rotateWriter {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("[FATAL] mkdir %s: %v", dir, err)
	}
	if maxAgeDays <= 0 {
		maxAgeDays = 7
	}
	w := &rotateWriter{dir: dir, maxAge: maxAgeDays}
	log.SetOutput(w)
	return w
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Printf("[WARN] invalid duration %q: %v", s, err)
		return 0
	}
	return d
}

func parsePortRange(s string) (config.PortRange, error) {
	if s == "" {
		return config.PortRange{}, nil
	}
	return config.ParsePortRange(s)
}

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
