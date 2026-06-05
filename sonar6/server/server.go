// Package server implements the IPv6 UDP echo server for the bitflip detection
// tool. It listens on the configured port range, validates incoming probe
// packets against the expected salt patterns, and echoes them back to the
// client while recording server-side bit-flip events.
package server

import (
	"bytes"
	"context"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv6"

	"github.com/baidu/nettools/sonar/codec"
	"github.com/baidu/nettools/sonar6/config"
	"github.com/baidu/nettools/stat"
)

// Server listens for IPv6 UDP probe packets and echoes them back to clients,
// while detecting and logging bit-flip corruption in the received payloads.
type Server struct {
	conf *config.Config

	mu      sync.RWMutex
	stats   map[string]stat.Stat // keyed by client IP
	localIP net.IP
	salts   map[int][]byte

	statProcessor *stat.Processor
	logger        *log.Logger
	sender        stat.Sender
}

// New creates a Server with the given configuration, statistics processor,
// and logger. It initializes four salt patterns matching the client for
// correct bit-flip detection and registers per-client stats.
// If sender is nil, a LogSender with the provided logger is used.
func New(conf *config.Config, statProcessor *stat.Processor, sender stat.Sender, logger *log.Logger) *Server {
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}

	if sender == nil {
		sender = stat.NewLogSender(logger, conf.Verbose)
	}

	localIP := net.ParseIP(conf.ServerAddr())
	if localIP == nil {
		logger.Printf("[ERRO] invalid server address: %s", conf.ServerAddr())
		return nil
	}

	s := &Server{
		conf:          conf,
		stats:         make(map[string]stat.Stat),
		statProcessor: statProcessor,
		logger:        logger,
		sender:        sender,
		salts: map[int][]byte{
			0: bytes.Repeat([]byte{0xFF}, conf.MsgLen-codec.MsgHeaderLen),
			1: bytes.Repeat([]byte{0x00}, conf.MsgLen-codec.MsgHeaderLen),
			2: bytes.Repeat([]byte{0x5A}, conf.MsgLen-codec.MsgHeaderLen),
			3: codec.ComplementaryBytes(conf.MsgLen - codec.MsgHeaderLen),
		},
		localIP: localIP,
	}

	for _, addr := range conf.ClientAddrs {
		s.logger.Printf("[INFO] prepare client: %s", addr)
		st := stat.NewServerStat(addr, conf.ServerAddr(),
			conf.ClientPortRange, conf.ServerPortRange,
			conf.RateInSpan, conf.Span, conf.Delay, s.sender)
		statProcessor.AddStat(st)
		canonicalKey := net.ParseIP(addr).String()
		s.stats[canonicalKey] = st
	}

	return s
}

// Run starts a read goroutine for each port in the server port range.
// It blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	portMin := s.conf.ServerPortRange.Min
	portMax := s.conf.ServerPortRange.Max
	for port := portMin; port <= portMax; port++ {
		go s.readPackets(port)
	}
	<-ctx.Done()
}

// readPackets listens on a single IPv6 UDP port, validates incoming probe packets,
// checks for bit-flip corruption against the expected salt (selected by seq%4),
// echoes the packet back, and records server-side statistics.
func (s *Server) readPackets(port int) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{Port: port, IP: s.localIP, Zone: s.conf.ServerZone})
	if err != nil {
		s.logger.Printf("[ERRO] listen UDP6 :%d: %v", port, err)
		return
	}
	_ = conn.SetReadBuffer(20 * 1024 * 1024)
	_ = conn.SetWriteBuffer(20 * 1024 * 1024)

	pconn := ipv6.NewPacketConn(conn)
	if err := pconn.SetTrafficClass(s.conf.TOS); err != nil {
		s.logger.Printf("[ERRO] set traffic class %d on port %d: %v", s.conf.TOS, port, err)
	} else {
		s.logger.Printf("[INFO] traffic class %d set for port %d", s.conf.TOS, port)
	}

	data := make([]byte, 10240)
	for {
		n, remote, err := conn.ReadFromUDP(data)
		if err != nil {
			s.logger.Printf("[ERRO] read UDP6 :%d: %v", port, err)
			continue
		}
		if n < codec.MsgHeaderLen || !codec.IsValid(data[:n]) {
			continue
		}

		seq, ts, lastSentCount, lastStartSrcPort, lastStartDstPort := codec.Decode(data[:n])

		hasBitflip := false
		if n == s.conf.MsgLen {
			salt := s.salts[int(seq%4)]
			if !bytes.Equal(salt, data[codec.MsgHeaderLen:n]) {
				hasBitflip = true
				for i, v := range data[codec.MsgHeaderLen:n] {
					if v != salt[i] {
						s.logger.Printf("[ERRO] [server bitflip] %s:%d -> %s:%d, %02x->%02x, idx: %d, seq: %d, ts: %d",
							remote.IP, remote.Port, s.localIP, port, salt[i], v, i+codec.MsgHeaderLen, seq, ts)
					}
				}
			}
		}

		_, _ = conn.WriteToUDP(data[:n], remote)

		st := s.getOrCreateStat(remote.IP.String())
		st.Put(uint16(remote.Port), uint16(port), seq, ts)
		st.ReceivedAndFix(seq, ts, time.Now().UnixNano()-ts, lastSentCount, lastStartSrcPort, lastStartDstPort, hasBitflip)
	}
}

func (s *Server) getOrCreateStat(clientIP string) stat.Stat {
	s.mu.RLock()
	st := s.stats[clientIP]
	s.mu.RUnlock()
	if st != nil {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.stats[clientIP]
	if st != nil {
		return st
	}

	s.logger.Printf("[INFO] auto-register client: %s", clientIP)
	st = stat.NewServerStat(clientIP, s.conf.ServerAddr(),
		s.conf.ClientPortRange, s.conf.ServerPortRange,
		s.conf.RateInSpan, s.conf.Span, s.conf.Delay, s.sender)
	s.statProcessor.AddStat(st)
	s.stats[clientIP] = st
	return st
}
