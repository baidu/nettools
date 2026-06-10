package server

import (
	"bytes"
	"context"
	"log"
	"net"
	"sync"

	"github.com/baidu/nettools/kuiniu/codec"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/transport"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"

	"github.com/smallnest/goscapy/pkg/packet"
)

// Server listens for probe packets on GPU NICs and echoes them back via GPU NIC.
type Server struct {
	conf          *config.Config
	statProcessor *stat.Processor
	logger        *log.Logger
	sender        stat.Sender
	salts         *util.Salts
	localGPUSet   map[string]struct{}

	mu    sync.RWMutex
	stats map[string]stat.Stat // keyed by client GPU IP
}

// noopSender is a silent Sender that discards all stat results.
type noopSender struct{}

func (*noopSender) Send(stat.StatResult) {}

// New creates a Server with the given configuration.
func New(conf *config.Config, statProcessor *stat.Processor, sender stat.Sender, logger *log.Logger) *Server {
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}
	if sender == nil {
		sender = &noopSender{}
	}

	localSet := make(map[string]struct{}, len(conf.LocalGPUAddrs))
	for _, addr := range conf.LocalGPUAddrs {
		localSet[addr] = struct{}{}
	}

	s := &Server{
		conf:          conf,
		statProcessor: statProcessor,
		logger:        logger,
		sender:        sender,
		salts:         util.NewSalts(conf.MsgLen - codec.MsgHeaderLen),
		stats:         make(map[string]stat.Stat),
		localGPUSet:   localSet,
	}

	for i, addr := range conf.RemoteGPUAddrs {
		st := stat.NewServerStat(addr, conf.LocalGPUAddrs[i],
			conf.ClientPortRange, conf.ServerPortRange,
			conf.RateInSpan, conf.Span, conf.Delay, sender)
		statProcessor.AddStat(st)
		s.stats[addr] = st
		s.logger.Printf("[INFO] [server] prepared client GPU: %s", addr)
	}

	return s
}

// Run starts GPU receivers and GPU echo senders. It blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.logger.Printf("[INFO] [server] creating GPU senders...")

	gpuSenders := make(map[int]transport.Sender)
	for i, gpuAddr := range s.conf.LocalGPUAddrs {
		gpuIP := net.ParseIP(gpuAddr)
		sender, err := transport.NewUDPSender(gpuIP, s.conf.TOS, 64, s.logger)
		if err != nil {
			s.logger.Printf("[ERRO] [GPU-%d] failed to create sender on %s: %v", i, gpuAddr, err)
			return err
		}
		gpuSenders[i] = sender
		defer func() { _ = sender.Close() }()
		s.logger.Printf("[INFO] [GPU-%d] sender bound to %s (TOS=%d)", i, gpuIP, s.conf.TOS)
	}

	// Create GPU receivers — one per GPU IP
	s.logger.Printf("[INFO] [server] creating GPU receivers...")
	for i, gpuAddr := range s.conf.LocalGPUAddrs {
		gpuIP := net.ParseIP(gpuAddr)
		r, err := transport.NewUDPReceiver(gpuIP, s.conf.TOS, s.conf.ServerPortRange, s.logger)
		if err != nil {
			s.logger.Printf("[ERRO] [GPU-%d] failed to create receiver on %s: %v", i, gpuAddr, err)
			continue
		}
		defer func() { _ = r.Close() }()
		s.logger.Printf("[INFO] [GPU-%d] listening on %s, ports %d-%d", i, gpuAddr, s.conf.ServerPortRange.Min, s.conf.ServerPortRange.Max)
		go s.readLoop(ctx, r, gpuSenders, i)
	}

	s.logger.Printf("[INFO] [server] all GPU receivers started, %d listening", len(s.conf.LocalGPUAddrs))
	<-ctx.Done()
	return nil
}

func (s *Server) readLoop(ctx context.Context, r transport.Receiver, gpuSenders map[int]transport.Sender, gpuIndex int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, remote, err := r.Receive(ctx)
		if err != nil {
			continue
		}
		s.handlePacket(data, remote, gpuSenders, gpuIndex)
	}
}

func (s *Server) handlePacket(rawPkt []byte, remote net.Addr, gpuSenders map[int]transport.Sender, gpuIndex int) {
	parsed, err := packet.DissectByProto(rawPkt, "UDP")
	if err != nil {
		return
	}
	rawLayer := parsed.GetLayer("Raw")
	if rawLayer == nil {
		return
	}
	loadVal, _ := rawLayer.Get("load")
	payload, _ := loadVal.([]byte)
	if len(payload) == 0 {
		return
	}

	if !codec.IsValid(payload) {
		return
	}

	r := codec.Decode(payload)

	// Skip packets that originated from one of our own local GPUs.
	// In role=both, raw sockets receive both inbound probes from peer
	// machines and echoes of our own outbound probes; the latter must
	// not be re-echoed (loop) or recorded as inbound traffic.
	clientGPUIP := net.IP(r.SrcIP).String()
	if _, ours := s.localGPUSet[clientGPUIP]; ours {
		return
	}

	// Detect server-side bitflip
	hasBitflip := false
	if len(payload) == s.conf.MsgLen {
		salt := s.salts.Get(r.Seq)
		if !bytes.Equal(salt, payload[codec.MsgHeaderLen:]) {
			hasBitflip = true
			for i, v := range payload[codec.MsgHeaderLen:] {
				if v != salt[i] {
					s.logger.Printf("[ERRO] [GPU-%d] [server bitflip] %s -> local, %02x->%02x, idx: %d, seq: %d, ts: %d",
						gpuIndex, remote.String(), salt[i], v, i+codec.MsgHeaderLen, r.Seq, r.Ts)
				}
			}
		}
	}

	// Record server-side stats
	st := s.getOrCreateStat(clientGPUIP)
	if st != nil {
		st.ReceivedAndFix(r.Seq, r.Ts, 0, r.LastSentCount, r.LastStartSrcPort, r.LastStartDstPort, hasBitflip)
	}

	// Echo back via GPU NIC to the client's GPU address
	sender := gpuSenders[gpuIndex]
	if sender == nil {
		return
	}
	clientGPUIPNet := net.IP(r.SrcIP)
	serverGPUIPNet := net.ParseIP(s.conf.LocalGPUAddrs[gpuIndex])
	_ = sender.Send(context.Background(), serverGPUIPNet, clientGPUIPNet, r.DstPort, r.SrcPort, payload)
}

func (s *Server) getOrCreateStat(clientGPUIP string) stat.Stat {
	s.mu.RLock()
	st := s.stats[clientGPUIP]
	s.mu.RUnlock()
	if st != nil {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.stats[clientGPUIP]
	if st != nil {
		return st
	}

	s.logger.Printf("[INFO] [server] auto-register client GPU: %s", clientGPUIP)
	st = stat.NewServerStat(clientGPUIP, s.conf.LocalGPUAddrs[0],
		s.conf.ClientPortRange, s.conf.ServerPortRange,
		s.conf.RateInSpan, s.conf.Span, s.conf.Delay, s.sender)
	s.statProcessor.AddStat(st)
	s.stats[clientGPUIP] = st
	return st
}
