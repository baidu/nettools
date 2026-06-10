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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/baidu/nettools/kuiniu/client"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/server"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/version"
	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
)

func main() {
	var (
		role           string
		localGPUAddrs  string
		remoteGPUAddrs string
		tos            int
		count          int
		sendDuration   time.Duration
		delay          time.Duration
		clientPorts    string
		serverPorts    string
		rate           int64
		msgLen         int
		verbose        bool
		configFile     string
		pprofAddr      string
		logDir         string
		logMaxAge      int
	)

	pflag.StringVarP(&role, "role", "r", "", "Role: client, server, or both")
	pflag.StringVarP(&localGPUAddrs, "local-gpu", "", "", "Comma-separated local GPU IP addresses")
	pflag.StringVarP(&remoteGPUAddrs, "remote-gpu", "", "", "Comma-separated remote GPU IP addresses")
	pflag.IntVarP(&tos, "tos", "t", 64, "IP TOS/DSCP value")
	pflag.IntVarP(&count, "count", "n", 0, "Max packets to send per GPU pair (0 = unlimited)")
	pflag.DurationVarP(&sendDuration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.DurationVar(&delay, "delay", 3*time.Second, "Delay before processing stats")
	pflag.StringVarP(&clientPorts, "client-ports", "", "43600,43699", "Client port range [min,max]")
	pflag.StringVarP(&serverPorts, "server-ports", "", "43600,43609", "Server port range [min,max]")
	pflag.Int64VarP(&rate, "rate", "", 5000, "Packets per span across all GPU pairs")
	pflag.IntVarP(&msgLen, "msglen", "", 1024, "Message payload size (excluding 44-byte header)")
	pflag.BoolVar(&verbose, "verbose", false, "Print per-port loss details on packet loss")
	pflag.StringVarP(&configFile, "config", "c", "", "Path to JSON config file (command-line flags override config values)")
	pflag.StringVar(&pprofAddr, "pprof", "", "Pprof listen address (e.g. :6060)")
	pflag.StringVar(&logDir, "log-dir", "", "Log directory for rotated log files")
	pflag.IntVar(&logMaxAge, "log-max-age", 7, "Max days to keep log files")

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

	// Start with config file (if provided), then overlay CLI flags.
	var cfg config.Config

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config %s: %v\n", configFile, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
			os.Exit(1)
		}
	}

	// CLI flags override config file values. Only override when the flag
	// was explicitly set by the user (non-zero for scalars, non-empty for strings).
	if role != "" {
		cfg.Role = config.Role(role)
	}
	if localGPUAddrs != "" {
		cfg.LocalGPUAddrs = splitNonEmpty(localGPUAddrs)
	}
	if remoteGPUAddrs != "" {
		cfg.RemoteGPUAddrs = splitNonEmpty(remoteGPUAddrs)
	}
	if pprofAddr != "" {
		cfg.PprofAddr = pprofAddr
	}
	if logDir != "" {
		cfg.LogDir = logDir
	}
	if logMaxAge != 7 {
		cfg.LogMaxAgeDays = logMaxAge
	}

	// Parse port ranges from CLI
	if clientPorts != "43600,43699" || cfg.ClientPortRangeStr == "" {
		cfg.ClientPortRangeStr = clientPorts
	}
	if serverPorts != "43600,43609" || cfg.ServerPortRangeStr == "" {
		cfg.ServerPortRangeStr = serverPorts
	}

	// Apply CLI overrides for numeric fields (only when explicitly different from defaults)
	if tos != 64 {
		cfg.TOS = tos
	}
	if count != 0 {
		cfg.Count = count
	}
	if sendDuration != 0 {
		cfg.SendDuration = sendDuration
		cfg.SendDurStr = sendDuration.String()
	}
	if rate != 5000 {
		cfg.RateInSpan = rate
	}
	if msgLen != 1024 {
		cfg.MsgLen = msgLen
	}
	cfg.Verbose = cfg.Verbose || verbose

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
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

	logger := log.Default()
	proc := stat.NewProcessor(cfg.Span, cfg.Delay)
	go proc.Run(ctx)

	runClient := cfg.Role == config.RoleClient || cfg.Role == config.RoleBoth
	runServer := cfg.Role == config.RoleServer || cfg.Role == config.RoleBoth

	if runClient {
		limiter := ratelimit.New(int(cfg.RateInSpan), ratelimit.Per(cfg.Span))
		c, err := client.NewClient(&cfg, limiter, proc, nil, logger)
		if err != nil {
			log.Printf("[ERRO] client init: %v", err)
		} else {
			go func() {
				if err := c.Run(ctx); err != nil {
					log.Printf("[ERRO] client: %v", err)
				}
			}()
			log.Printf("[INFO] kuiniu client started, %d GPU pairs", cfg.GPUPairCount())
		}
	}

	if runServer {
		s := server.New(&cfg, proc, nil, logger)
		go func() {
			if err := s.Run(ctx); err != nil {
				log.Printf("[ERRO] server: %v", err)
			}
		}()
		log.Printf("[INFO] kuiniu server started, %d GPU IPs", cfg.GPUPairCount())
	}

	<-ctx.Done()
	time.Sleep(1 * time.Second)
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
		name := "kuiniu.log." + today
		f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			w.date = ""
			return 0, fmt.Errorf("open log file: %w", err)
		}
		w.file = f
		w.date = today
		link := filepath.Join(w.dir, "kuiniu.log")
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
		if !strings.HasPrefix(e.Name(), "kuiniu.log.") {
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
	// Write to both file and stderr so the user sees output in the terminal
	log.SetOutput(io.MultiWriter(os.Stderr, w))
	return w
}
