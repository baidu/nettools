package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baidu/nettools/sonar/client"
	"github.com/baidu/nettools/sonar/config"
	"github.com/baidu/nettools/sonar/server"
	"github.com/baidu/nettools/stat"
	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
)

func main() {
	var (
		role         string
		clientAddr   string
		serverAddr   string
		tos          int
		count        int
		sendDuration time.Duration
		delay        time.Duration
		clientPorts  string
		serverPorts  string
		rate         int64
		msgLen       int
		verbose      bool
	)

	pflag.StringVarP(&role, "role", "r", "server", "Role: client or server")
	pflag.StringVarP(&clientAddr, "client-addr", "c", "", "Client IP address (auto-detected if empty)")
	pflag.StringVarP(&serverAddr, "server-addr", "s", "", "Server IP address (auto-detected for server role if empty)")
	pflag.IntVarP(&tos, "tos", "t", 64, "IP TOS/DSCP value")
	pflag.IntVarP(&count, "count", "n", 0, "Max packets to send (0 = unlimited)")
	pflag.DurationVarP(&sendDuration, "duration", "d", 0, "Max send duration (0 = unlimited)")
	pflag.StringVarP(&clientPorts, "client-ports", "", "43500,43599", "Client port range [min,max]")
	pflag.StringVarP(&serverPorts, "server-ports", "", "43500,43509", "Server port range [min,max]")
	pflag.Int64VarP(&rate, "rate", "", 5000, "Packets per span")
	pflag.IntVarP(&msgLen, "msglen", "", 1024, "Message payload size (excluding 28-byte header)")
	pflag.DurationVar(&delay, "delay", 3*time.Second, "Delay before processing stats (waiting for in-flight packets)")
	pflag.BoolVar(&verbose, "verbose", false, "Print per-port loss details on packet loss")

	pflag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cpr, err := config.ParsePortRange(clientPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid client port range: %v\n", err)
		os.Exit(1)
	}
	spr, err := config.ParsePortRange(serverPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid server port range: %v\n", err)
		os.Exit(1)
	}

	cfg := &config.Config{
		Role:            config.Role(role),
		ClientAddr:      clientAddr,
		ClientAddrs:     splitNonEmpty(clientAddr),
		ServerAddrs:     splitNonEmpty(serverAddr),
		TOS:             tos,
		ClientPortRange: cpr,
		ServerPortRange: spr,
		RateInSpan:      rate,
		Span:            time.Second,
		Delay:           delay,
		MsgLen:          msgLen,
		Count:           count,
		SendDuration:    sendDuration,
		Verbose:         verbose,
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := log.Default()

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("[INFO] received signal, shutting down...")
		cancel()
	}()

	switch cfg.Role {
	case config.RoleClient:
		runClient(ctx, cfg, logger)
	case config.RoleServer:
		runServer(ctx, cfg, logger)
	}

	// Wait for goroutines to finish after context cancellation.
	// For server, the main goroutine exits when ctx is cancelled
	// via the signal handler above.
	time.Sleep(1 * time.Second)
}

func runClient(ctx context.Context, cfg *config.Config, logger *log.Logger) {
	proc := stat.NewProcessor(cfg.Span, cfg.Delay)
	go proc.Run(ctx)

	limiter := ratelimit.New(int(cfg.RateInSpan), ratelimit.Per(cfg.Span))
	c := client.NewClient(cfg, limiter, proc, nil, logger)
	c.ExitOnReachLimit = false

	go func() {
		if err := c.Run(ctx); err != nil {
			log.Printf("[ERRO] client error: %v", err)
		}
	}()

	log.Printf("[INFO] client %s -> %v", cfg.ClientAddr, cfg.ServerAddrs)
	<-ctx.Done()
}

func runServer(ctx context.Context, cfg *config.Config, logger *log.Logger) {
	proc := stat.NewProcessor(cfg.Span, cfg.Delay)
	go proc.Run(ctx)

	s := server.New(cfg, proc, nil, logger)
	s.Run(ctx)
	log.Printf("[INFO] server %s for clients %v", cfg.ServerAddr(), cfg.ClientAddrs)
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
