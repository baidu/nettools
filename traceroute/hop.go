package traceroute

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
)

// ProbeResult is the outcome of a single probe sent at a given TTL.
type ProbeResult struct {
	// FromIP is the source IP of the ICMP Time Exceeded / Port Unreachable
	// reply (or the destination itself when reached). Empty on timeout.
	FromIP net.IP
	// RTT is the round-trip time of this probe.
	RTT time.Duration
	// Reached is true if this probe reached the final destination.
	Reached bool
	// TimedOut is true if no reply was received within the timeout.
	TimedOut bool
}

// Hop aggregates all probes sent for a single TTL.
type Hop struct {
	TTL    int
	Probes []ProbeResult

	// Addrs holds the distinct responding IPs seen at this TTL, in first-seen
	// order (ECMP may surface more than one).
	Addrs []net.IP
	// Hosts holds the reverse-DNS name per Addrs entry (empty if unresolved).
	Hosts []string
}

// sortedRTTs returns the RTTs of probes that got a reply, ascending.
func (h *Hop) sortedRTTs() []time.Duration {
	var rtts []time.Duration
	for _, p := range h.Probes {
		if !p.TimedOut {
			rtts = append(rtts, p.RTT)
		}
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts
}

// Received returns the number of probes that got a reply.
func (h *Hop) Received() int {
	n := 0
	for _, p := range h.Probes {
		if !p.TimedOut {
			n++
		}
	}
	return n
}

// LossRate returns the fraction of probes [0,1] that timed out.
func (h *Hop) LossRate() float64 {
	if len(h.Probes) == 0 {
		return 0
	}
	lost := len(h.Probes) - h.Received()
	return float64(lost) / float64(len(h.Probes))
}

// MinRTT, AvgRTT, MaxRTT return latency stats over replied probes.
func (h *Hop) MinRTT() time.Duration {
	rtts := h.sortedRTTs()
	if len(rtts) == 0 {
		return 0
	}
	return rtts[0]
}

func (h *Hop) MaxRTT() time.Duration {
	rtts := h.sortedRTTs()
	if len(rtts) == 0 {
		return 0
	}
	return rtts[len(rtts)-1]
}

func (h *Hop) AvgRTT() time.Duration {
	rtts := h.sortedRTTs()
	if len(rtts) == 0 {
		return 0
	}
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	return sum / time.Duration(len(rtts))
}

// Reached reports whether any probe at this TTL reached the destination.
func (h *Hop) Reached() bool {
	for _, p := range h.Probes {
		if p.Reached {
			return true
		}
	}
	return false
}

// Result is the full traceroute result for one target.
type Result struct {
	Dst     string
	DstIP   net.IP
	Proto   Protocol
	MaxHops int
	Hops    []Hop
	Reached bool
}

// addAddr records a distinct responding IP (and its eventual hostname slot).
func (h *Hop) addAddr(ip net.IP) {
	for _, a := range h.Addrs {
		if a.Equal(ip) {
			return
		}
	}
	h.Addrs = append(h.Addrs, ip)
	h.Hosts = append(h.Hosts, "")
}

// extractReply pulls the responding source IP and reachability flags out of a
// goscapy-dissected reply packet. All decoding goes through goscapy layers.
func extractReply(proto Protocol, resp *packet.Packet) (from net.IP, reached bool) {
	ipLayer := resp.GetLayer("IP")
	if ipLayer != nil {
		if v, err := ipLayer.Get("src"); err == nil && v != nil {
			if ip, ok := v.(net.IP); ok {
				from = ip
			}
		}
	}

	if icmp := resp.GetLayer("ICMP"); icmp != nil {
		if v, err := icmp.Get("type"); err == nil && v != nil {
			if t, ok := v.(uint8); ok {
				switch t {
				case 0: // Echo Reply — ICMP probe reached destination
					reached = true
				case 3: // Destination Unreachable — UDP probe reached destination
					if proto == ProtoUDP {
						reached = true
					}
				}
			}
		}
	}

	// TCP SYN-ACK or RST means the TCP probe reached the destination.
	if proto == ProtoTCP {
		if tcp := resp.GetLayer("TCP"); tcp != nil {
			if v, err := tcp.Get("flags"); err == nil && v != nil {
				if flags, ok := v.(uint8); ok {
					if flags&layers.TCPSyn != 0 || flags&layers.TCPRst != 0 {
						reached = true
					}
				}
			}
		}
	}

	return from, reached
}

// resolveHosts fills in reverse-DNS names for every distinct hop address,
// concurrently and with deduplication across hops.
func resolveHosts(results []*Result) {
	cache := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	lookup := func(ip net.IP) {
		key := ip.String()
		mu.Lock()
		if _, done := cache[key]; done {
			mu.Unlock()
			return
		}
		cache[key] = "" // mark in-flight to avoid duplicate lookups
		mu.Unlock()

		var name string
		if names, err := net.LookupAddr(key); err == nil && len(names) > 0 {
			name = names[0]
		}
		mu.Lock()
		cache[key] = name
		mu.Unlock()
	}

	for _, r := range results {
		for hi := range r.Hops {
			for _, addr := range r.Hops[hi].Addrs {
				wg.Add(1)
				go func(ip net.IP) {
					defer wg.Done()
					lookup(ip)
				}(addr)
			}
		}
	}
	wg.Wait()

	for _, r := range results {
		for hi := range r.Hops {
			for ai, addr := range r.Hops[hi].Addrs {
				r.Hops[hi].Hosts[ai] = cache[addr.String()]
			}
		}
	}
}
