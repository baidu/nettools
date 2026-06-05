// Package stat provides time-bucketed statistics collection for UDP probe
// packets. It tracks per-bucket sent/received counts, loss rates, RTT, and
// bit-flip events, and periodically reports summary via a pluggable Sender.
package stat

import "time"

// Sender is the interface for consuming aggregated stat results.
// Implementations can write to logs, send to Kafka, push to ClickHouse, etc.
type Sender interface {
	// Send is called once per time bucket with the aggregated statistics.
	Send(result StatResult)
}

// StatResult holds the aggregated statistics for a single time bucket.
type StatResult struct {
	Timestamp         time.Time
	ClientAddr        string
	ServerAddr        string
	ServerSide        bool
	Sent              int
	Received          int
	Loss              int
	LossRate          float64
	AvgRTT            int64
	MaxRTT            int64
	LossPorts         map[int]int
	BitflipPorts      map[int]int
	LossPortsCount    map[string]int
	BitflipPortsCount map[string]int
}

// Stat is the interface for recording probe packet statistics.
// Implementations track sent, received, lost, and bit-flipped packets
// within time-bucketed windows.
type Stat interface {
	statOnce()

	// Put records a sent probe packet.
	Put(clientPort, serverPort uint16, seq uint64, ts int64)
	// Delete removes a sent record (e.g. when the send itself failed).
	Delete(seq uint64, ts int64)
	// Received marks a probe packet as received and records its RTT.
	Received(seq uint64, ts, rtt int64, hasBitflip bool)
	// ReceivedAndFix marks a probe as received and corrects the previous
	// bucket's sent count and starting ports using values from the client.
	ReceivedAndFix(seq uint64, ts, rtt int64, lastSentCount uint32, lastStartSrcPort, lastStartDstPort uint16, hasBitflip bool)
}

// PortRange represents an inclusive range of UDP port numbers.
type PortRange struct {
	Min int
	Max int
}

// GetNextPorts advances the port pair in odometer style: dstPort increments
// first; on wrap it resets and srcPort increments.
func GetNextPorts(clientPort, serverPort uint16, clientPortRange, serverPortRange PortRange) (uint16, uint16) {
	serverPort++
	if serverPort > uint16(serverPortRange.Max) {
		serverPort = uint16(serverPortRange.Min)
		clientPort++
	}
	if clientPort > uint16(clientPortRange.Max) {
		clientPort = uint16(clientPortRange.Min)
	}
	return clientPort, serverPort
}

// statResult holds the aggregated statistics for a single time bucket.
type statResult struct {
	sent              int
	received          int
	loss              int
	lossRate          float64
	rtt               int64
	maxRTT            int64
	lossPorts         map[int]int
	bitflipPorts      map[int]int
	lossPortsCount    map[string]int
	bitflipPortsCount map[string]int
}
