package stat

import (
	"fmt"
	"log"
	"time"
)

// LogSender implements Sender by writing stat results to a *log.Logger.
type LogSender struct {
	logger  *log.Logger
	verbose bool
}

// NewLogSender creates a LogSender that writes to the given logger.
// When verbose is true, per-port loss details are included.
func NewLogSender(logger *log.Logger, verbose bool) *LogSender {
	return &LogSender{logger: logger, verbose: verbose}
}

// Send writes the StatResult to the logger. Loss-free buckets are logged at
// INFO level; buckets with loss are logged at WARN level with additional
// loss-port details when verbose is enabled.
func (s *LogSender) Send(r StatResult) {
	ts := r.Timestamp.Format("15:04:05")
	if r.ServerSide {
		if r.Loss == 0 {
			s.logger.Printf("[INFO] %s, [%s -> %s], sent: %d, received: %d, loss: %d, loss rate: %.2f%%",
				ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, r.Loss, r.LossRate*100)
		} else {
			s.logger.Printf("[WARN] %s, [%s -> %s], sent: %d, received: %d, loss: %d, loss rate: %.2f%%",
				ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, r.Loss, r.LossRate*100)
			if s.verbose {
				s.logger.Printf("[WARN] %s, [%s -> %s], loss ports: %v", ts, r.ClientAddr, r.ServerAddr, r.LossPorts)
			}
		}
	} else if r.Loss == 0 {
		s.logger.Printf("[INFO] %s, [%s -> %s], sent: %d, received: %d, loss: %d, loss rate: %.2f%%, avg rtt: %v ns",
			ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, r.Loss, r.LossRate*100, r.AvgRTT)
	} else {
		s.logger.Printf("[WARN] %s, [%s -> %s], sent: %d, received: %d, loss: %d, loss rate: %.2f%%, avg rtt: %v ns",
			ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, r.Loss, r.LossRate*100, r.AvgRTT)
		if s.verbose {
			s.logger.Printf("[WARN] %s, [%s -> %s], loss ports: %v", ts, r.ClientAddr, r.ServerAddr, r.LossPorts)
		}
	}
}

// udpStat implements the Stat interface for a single client-server probe pair.
// It delegates storage to a time-bucketed buckets instance and periodically
// sends aggregated results via a Sender.
type udpStat struct {
	clientAddr      string
	serverAddr      string
	clientPortRange PortRange
	serverPortRange PortRange
	lastID          int64
	serverSide      bool

	bkts       *buckets
	rateInSpan int64
	span       time.Duration
	delay      time.Duration

	sender Sender
}

// NewStat creates a Stat instance that tracks probe statistics between
// the given client and server address over the configured port ranges.
// Results are sent via the provided Sender.
func NewStat(clientAddr, serverAddr string, clientPortRange, serverPortRange PortRange,
	rateInSpan int64, span, delay time.Duration, sender Sender) Stat {
	return &udpStat{
		bkts:            newBuckets(span, rateInSpan, false),
		clientAddr:      clientAddr,
		serverAddr:      serverAddr,
		clientPortRange: clientPortRange,
		serverPortRange: serverPortRange,
		rateInSpan:      rateInSpan,
		span:            span,
		delay:           delay,
		sender:          sender,
	}
}

// NewServerStat creates a server-side Stat instance that tracks probe
// statistics for the given client-server pair. Results are sent via
// the provided Sender.
func NewServerStat(clientAddr, serverAddr string, clientPortRange, serverPortRange PortRange,
	rateInSpan int64, span, delay time.Duration, sender Sender) Stat {
	return &udpStat{
		bkts:            newBuckets(span, rateInSpan, true),
		clientAddr:      clientAddr,
		serverAddr:      serverAddr,
		clientPortRange: clientPortRange,
		serverPortRange: serverPortRange,
		rateInSpan:      rateInSpan,
		span:            span,
		delay:           delay,
		serverSide:      true,
		sender:          sender,
	}
}

// statOnce processes the oldest time bucket that has passed the delay
// window. It computes loss/received/RTT statistics, sends them via
// the Sender, and removes the bucket. Buckets that haven't aged past
// the delay are skipped.
func (s *udpStat) statOnce() {
	lastID := s.lastID
	b := s.bkts.oldest()

	if b != nil && lastID > 0 && b.id > 0 &&
		time.Now().Add(-s.delay).UnixNano()/int64(s.span) < b.id {
		return
	}

	for b != nil {
		if b.id <= lastID {
			s.bkts.remove(b.id)
			b = s.bkts.oldest()
			continue
		}
		break
	}
	if b == nil {
		return
	}

	s.lastID = b.id

	sr := b.stat()

	if s.serverSide {
		sr.lossPorts, sr.lossPortsCount = s.computeServerLossPorts(b)
	}

	if s.lastID > 0 && s.sender != nil {
		s.sender.Send(StatResult{
			Timestamp:         time.Unix(0, b.startNano),
			ClientAddr:        s.clientAddr,
			ServerAddr:        s.serverAddr,
			ServerSide:        s.serverSide,
			Sent:              sr.sent,
			Received:          sr.received,
			Loss:              sr.loss,
			LossRate:          sr.lossRate,
			AvgRTT:            sr.rtt,
			MaxRTT:            sr.maxRTT,
			LossPorts:         sr.lossPorts,
			BitflipPorts:      sr.bitflipPorts,
			LossPortsCount:    sr.lossPortsCount,
			BitflipPortsCount: sr.bitflipPortsCount,
		})
	}
	s.bkts.remove(b.id)
}

// computeServerLossPorts computes lost port pairs by comparing the expected
// set (derived from startSrcPort/startDstPort/packetCount) against actually
// received port pairs.
func (s *udpStat) computeServerLossPorts(b *bucket) (map[int]int, map[string]int) {
	b.RLock()
	packetCount := b.packetCount
	startSrc := b.startSrcPort
	startDst := b.startDstPort
	fixed := b.packetCountFixed
	b.RUnlock()

	if !fixed || packetCount == 0 || (startSrc == 0 && startDst == 0) {
		return nil, nil
	}

	type portPair struct {
		src, dst uint16
	}

	expectedCounts := make(map[portPair]int)
	src, dst := startSrc, startDst
	for i := uint32(0); i < packetCount; i++ {
		src, dst = GetNextPorts(src, dst, s.clientPortRange, s.serverPortRange)
		expectedCounts[portPair{src, dst}]++
	}

	receivedCounts := make(map[portPair]int)
	b.RLock()
	for _, r := range b.requests {
		if r.rtt != rttUnset && r.clientPort != 0 {
			receivedCounts[portPair{r.clientPort, r.serverPort}]++
		}
	}
	b.RUnlock()

	lossPorts := make(map[int]int)
	lossPortsCount := make(map[string]int)
	var portKeyBuf [24]byte
	for pp, expected := range expectedCounts {
		received := receivedCounts[pp]
		if received < expected {
			lossPorts[int(pp.src)] = int(pp.dst)
			key := fmt.Appendf(portKeyBuf[:0], "%d-%d", pp.src, pp.dst)
			lossPortsCount[string(key)] = expected - received
		}
	}

	return lossPorts, lossPortsCount
}

func (s *udpStat) Put(clientPort, serverPort uint16, seq uint64, ts int64) {
	s.bkts.put(clientPort, serverPort, seq, ts)
}

func (s *udpStat) Delete(seq uint64, ts int64) { s.bkts.delete(seq, ts) }

func (s *udpStat) Received(seq uint64, ts, rtt int64, hasBitflip bool) {
	s.bkts.received(seq, ts, rtt, hasBitflip)
}

func (s *udpStat) ReceivedAndFix(seq uint64, ts, rtt int64, lastSentCount uint32, lastStartSrcPort, lastStartDstPort uint16, hasBitflip bool) {
	s.bkts.receivedAndFix(seq, ts, rtt, lastSentCount, lastStartSrcPort, lastStartDstPort, hasBitflip)
}
