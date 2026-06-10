package client

import (
	"bytes"
	"context"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/baidu/nettools/kuiniu/codec"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/transport"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"

	"github.com/smallnest/goscapy/pkg/packet"
	"go.uber.org/ratelimit"
)

type gpuPeer struct {
	gpuIndex        int
	localGPUIP      net.IP
	remoteGPUIP     net.IP
	seq             *uint64
	stat            stat.Stat
	msgLen          int
	clientPortRange config.PortRange
	serverPortRange config.PortRange
	ports           atomic.Uint32
}

func packPorts(local, server uint16) uint32 {
	return uint32(local)<<16 | uint32(server)
}

func unpackPorts(v uint32) (local, server uint16) {
	return uint16(v >> 16), uint16(v)
}

// Client sends probe packets from GPU NICs and receives echoes on GPU NICs.
type Client struct {
	conf          *config.Config
	limiter       ratelimit.Limiter
	statProcessor *stat.Processor
	logger        *log.Logger
	sender        stat.Sender
	salts         *util.Salts
	peers         []*gpuPeer
	gpuReceivers  []transport.Receiver
	delayBitflip  time.Duration
}

// NewClient creates a Client that probes GPU[i] -> remote GPU[i].
func NewClient(conf *config.Config, limiter ratelimit.Limiter,
	statProcessor *stat.Processor, sender stat.Sender, logger *log.Logger,
) (*Client, error) {
	if conf.MsgLen < codec.MsgHeaderLen {
		conf.MsgLen = codec.MsgHeaderLen
	}
	if sender == nil {
		sender = stat.NewLogSender(logger, conf.Verbose)
	}

	c := &Client{
		conf:          conf,
		limiter:       limiter,
		logger:        logger,
		sender:        sender,
		statProcessor: statProcessor,
		salts:         util.NewSalts(conf.MsgLen - codec.MsgHeaderLen),
		delayBitflip:  10 * time.Second,
	}

	for i := 0; i < conf.GPUPairCount(); i++ {
		seq := uint64(rand.Int63())
		p := &gpuPeer{
			gpuIndex:        i,
			localGPUIP:      net.ParseIP(conf.LocalGPUAddrs[i]),
			remoteGPUIP:     net.ParseIP(conf.RemoteGPUAddrs[i]),
			seq:             &seq,
			msgLen:          conf.MsgLen,
			clientPortRange: conf.ClientPortRange,
			serverPortRange: conf.ServerPortRange,
		}
		p.ports.Store(packPorts(uint16(conf.ClientPortRange.Min), uint16(conf.ServerPortRange.Min)))

		s := stat.NewStat(conf.LocalGPUAddrs[i], conf.RemoteGPUAddrs[i],
			conf.ClientPortRange, conf.ServerPortRange,
			conf.RateInSpan, conf.Span, conf.Delay, c.sender)
		statProcessor.AddStat(s)
		p.stat = s

		c.peers = append(c.peers, p)
		c.logger.Printf("[INFO] [GPU-%d] configured peer %s -> %s", i, conf.LocalGPUAddrs[i], conf.RemoteGPUAddrs[i])
	}

	return c, nil
}

// Run starts the client: opens GPU senders and GPU receivers, then enters the send loop.
func (c *Client) Run(ctx context.Context) error {
	c.logger.Printf("[INFO] [client] creating GPU senders...")

	gpuSenders := make(map[int]transport.Sender)
	for _, p := range c.peers {
		s, err := transport.NewUDPSender(p.localGPUIP, c.conf.TOS, 64, c.logger)
		if err != nil {
			c.logger.Printf("[ERRO] [GPU-%d] failed to create sender on %s: %v", p.gpuIndex, p.localGPUIP, err)
			return err
		}
		gpuSenders[p.gpuIndex] = s
		defer func() { _ = s.Close() }()
		c.logger.Printf("[INFO] [GPU-%d] sender bound to %s (TOS=%d)", p.gpuIndex, p.localGPUIP, c.conf.TOS)
	}

	c.logger.Printf("[INFO] [client] creating GPU receivers...")

	pr := c.conf.ClientPortRange
	portCount := pr.Max - pr.Min + 1
	gcount := min(portCount, 8)
	portsPerG := (portCount + gcount - 1) / gcount

	for _, p := range c.peers {
		for i := pr.Min; i <= pr.Max; i += portsPerG {
			upper := i + portsPerG - 1
			if upper > pr.Max {
				upper = pr.Max
			}
			r, err := transport.NewUDPReceiver(p.localGPUIP, c.conf.TOS, config.PortRange{Min: i, Max: upper}, c.logger)
			if err != nil {
				c.logger.Printf("[ERRO] [GPU-%d] failed to create receiver on %s (ports %d-%d): %v", p.gpuIndex, p.localGPUIP, i, upper, err)
				return err
			}
			c.gpuReceivers = append(c.gpuReceivers, r)
			defer func() { _ = r.Close() }()
			c.logger.Printf("[INFO] [GPU-%d] receiver on %s, ports %d-%d", p.gpuIndex, p.localGPUIP, i, upper)
		}
	}

	for _, r := range c.gpuReceivers {
		go c.readLoop(ctx, r)
	}

	c.logger.Printf("[INFO] [client] waiting 3s for receivers to stabilize...")
	time.Sleep(3 * time.Second)

	c.logger.Printf("[INFO] [client] starting probe: %d GPU pairs, rate=%d/span, span=%v, msgLen=%d",
		len(c.peers), c.conf.RateInSpan, c.conf.Span, c.conf.MsgLen)
	return c.serveWrite(ctx, gpuSenders)
}

func (c *Client) serveWrite(ctx context.Context, gpuSenders map[int]transport.Sender) error {
	span := int64(c.conf.Span)
	c.logger.Printf("[INFO] client TOS: %d, span: %v, GPU pairs: %d", c.conf.TOS, c.conf.Span, len(c.peers))

	bucketIDs := make(map[*gpuPeer]int64)
	lastSent := make(map[*gpuPeer]uint32)
	curSent := make(map[*gpuPeer]uint32)
	lastStartSrcPort := make(map[*gpuPeer]uint16)
	lastStartDstPort := make(map[*gpuPeer]uint16)
	curStartSrcPort := make(map[*gpuPeer]uint16)
	curStartDstPort := make(map[*gpuPeer]uint16)
	for _, p := range c.peers {
		curSent[p] = uint32(c.conf.RateInSpan)
		curStartSrcPort[p] = uint16(c.conf.ClientPortRange.Min)
		curStartDstPort[p] = uint16(c.conf.ServerPortRange.Min)
	}

	count := 0
	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.limiter.Take()

		for _, p := range c.peers {
			bizSeq := atomic.AddUint64(p.seq, 1)
			localPort, serverPort := unpackPorts(p.ports.Load())
			localPort, serverPort = config.GetNextPorts(localPort, serverPort, p.clientPortRange, p.serverPortRange)
			p.ports.Store(packPorts(localPort, serverPort))

			ts := time.Now().UnixNano()
			bucketID := ts / span
			if bucketID != bucketIDs[p] {
				bucketIDs[p] = bucketID
				lastSent[p] = curSent[p]
				lastStartSrcPort[p] = curStartSrcPort[p]
				lastStartDstPort[p] = curStartDstPort[p]
				curSent[p] = 1
				curStartSrcPort[p] = localPort
				curStartDstPort[p] = serverPort
			} else {
				curSent[p]++
			}

			salt := c.salts.Get(bizSeq)
			payload := codec.Encode(bizSeq, salt, ts, p.msgLen,
				p.localGPUIP.To4(), p.remoteGPUIP.To4(),
				localPort, serverPort,
				lastSent[p], lastStartSrcPort[p], lastStartDstPort[p])

			count++
			if c.conf.Count > 0 && count > c.conf.Count {
				c.logger.Printf("[INFO] reached count limit")
				return nil
			}
			if c.conf.SendDuration > 0 && time.Since(start) > c.conf.SendDuration {
				c.logger.Printf("[INFO] reached duration limit")
				return nil
			}

			p.stat.Put(localPort, serverPort, bizSeq, ts)
			sender := gpuSenders[p.gpuIndex]
			if err := sender.Send(ctx, p.localGPUIP, p.remoteGPUIP, localPort, serverPort, payload); err != nil {
				p.stat.Delete(bizSeq, ts)
			}
		}
	}
}

var startupTime = time.Now()

func (c *Client) readLoop(ctx context.Context, r transport.Receiver) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, _, err := r.Receive(ctx)
		if err != nil {
			continue
		}
		c.handlePacket(data)
	}
}

func (c *Client) handlePacket(rawPkt []byte) {
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

	var p *gpuPeer
	for _, peer := range c.peers {
		if peer.remoteGPUIP.Equal(r.DstIP) {
			p = peer
			break
		}
	}
	if p == nil {
		return
	}

	hasBitflip := false
	if len(payload) == c.conf.MsgLen {
		salt := c.salts.Get(r.Seq)
		if !bytes.Equal(salt, payload[codec.MsgHeaderLen:]) {
			hasBitflip = c.detectBitflip(p, payload, salt, r)
			if hasBitflip {
				return
			}
		}
	}

	p.stat.Received(r.Seq, r.Ts, time.Now().UnixNano()-r.Ts, hasBitflip)
}

func (c *Client) detectBitflip(p *gpuPeer, payload, salt []byte, r codec.DecodeResult) bool {
	if time.Since(startupTime) <= c.delayBitflip {
		return false
	}

	for i, v := range payload[codec.MsgHeaderLen:] {
		if v != salt[i] {
			localPort, serverPort := unpackPorts(p.ports.Load())
			c.logger.Printf("[ERRO] [GPU-%d] [client bitflip] %s:%d -> %s:%d, %02x->%02x, idx: %d, seq: %d, ts: %d",
				p.gpuIndex, p.localGPUIP, localPort, p.remoteGPUIP, serverPort,
				salt[i], v, i+codec.MsgHeaderLen, r.Seq, r.Ts)
		}
	}
	return true
}

// Close closes all receivers.
func (c *Client) Close() {
	for _, r := range c.gpuReceivers {
		_ = r.Close()
	}
}
