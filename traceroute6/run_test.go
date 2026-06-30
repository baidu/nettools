package traceroute6

import (
	"testing"
	"time"
)

func TestHopStats(t *testing.T) {
	h := &Hop{
		Probes: []ProbeResult{
			{RTT: 2 * time.Millisecond},
			{RTT: 6 * time.Millisecond},
			{RTT: 4 * time.Millisecond},
			{TimedOut: true},
		},
	}
	if got := h.Received(); got != 3 {
		t.Errorf("Received = %d, want 3", got)
	}
	if got := h.LossRate(); got != 0.25 {
		t.Errorf("LossRate = %v, want 0.25", got)
	}
	if got := h.MinRTT(); got != 2*time.Millisecond {
		t.Errorf("MinRTT = %v, want 2ms", got)
	}
	if got := h.MaxRTT(); got != 6*time.Millisecond {
		t.Errorf("MaxRTT = %v, want 6ms", got)
	}
	if got := h.AvgRTT(); got != 4*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 4ms", got)
	}
}

func TestHopStatsAllTimeout(t *testing.T) {
	h := &Hop{Probes: []ProbeResult{{TimedOut: true}, {TimedOut: true}}}
	if h.Received() != 0 {
		t.Errorf("Received should be 0")
	}
	if h.LossRate() != 1 {
		t.Errorf("LossRate should be 1")
	}
	if h.MinRTT() != 0 || h.MaxRTT() != 0 || h.AvgRTT() != 0 {
		t.Errorf("RTT stats should be 0 when no replies")
	}
}

func TestHopLossRateNoProbes(t *testing.T) {
	h := &Hop{}
	if h.LossRate() != 0 {
		t.Errorf("LossRate with no probes should be 0")
	}
}

func TestAddAddrDedup(t *testing.T) {
	h := &Hop{}
	h.addAddr(mustV6("2001:db8::1"))
	h.addAddr(mustV6("2001:db8::1")) // duplicate, ignored
	h.addAddr(mustV6("2001:db8::2"))
	if len(h.Addrs) != 2 {
		t.Fatalf("Addrs len = %d, want 2", len(h.Addrs))
	}
	if len(h.Hosts) != 2 || len(h.Infos) != 2 {
		t.Errorf("Hosts/Infos should track Addrs length")
	}
	if !h.Addrs[0].Equal(mustV6("2001:db8::1")) || !h.Addrs[1].Equal(mustV6("2001:db8::2")) {
		t.Errorf("Addrs first-seen order wrong: %v", h.Addrs)
	}
}

func TestHopReached(t *testing.T) {
	h := &Hop{Probes: []ProbeResult{{TimedOut: true}, {Reached: true}}}
	if !h.Reached() {
		t.Errorf("Hop with a reached probe should report Reached")
	}
	h2 := &Hop{Probes: []ProbeResult{{TimedOut: true}}}
	if h2.Reached() {
		t.Errorf("Hop with no reached probe should not report Reached")
	}
}

func TestFinalizeTrimsBeyondReached(t *testing.T) {
	res := &Result{
		Hops: []Hop{
			{TTL: 1, Probes: []ProbeResult{{FromIP: mustV6("2001:db8::1"), RTT: time.Millisecond}}},
			{TTL: 2, Probes: []ProbeResult{{FromIP: mustV6("2001:db8::2"), RTT: time.Millisecond}}},
			{TTL: 3, Probes: []ProbeResult{{FromIP: mustV6("2001:4860:4860::8888"), RTT: time.Millisecond, Reached: true}}},
			{TTL: 4, Probes: []ProbeResult{{TimedOut: true}}},
			{TTL: 5, Probes: []ProbeResult{{TimedOut: true}}},
		},
	}
	tr := NewTracer(DefaultConfig())
	tr.finalize(res)

	if !res.Reached {
		t.Errorf("result should be marked reached")
	}
	if len(res.Hops) != 3 {
		t.Errorf("hops should be trimmed to 3, got %d", len(res.Hops))
	}
}

func TestFinalizeUnreached(t *testing.T) {
	res := &Result{
		Hops: []Hop{
			{TTL: 1, Probes: []ProbeResult{{TimedOut: true}}},
			{TTL: 2, Probes: []ProbeResult{{TimedOut: true}}},
		},
	}
	tr := NewTracer(DefaultConfig())
	tr.finalize(res)

	if res.Reached {
		t.Errorf("result should not be marked reached")
	}
	if len(res.Hops) != 2 {
		t.Errorf("hops should be untouched, got %d", len(res.Hops))
	}
}

func TestRunRejectsNonV6Target(t *testing.T) {
	conf := DefaultConfig()
	conf.Targets = []string{"8.8.8.8"} // IPv4 — produces an empty placeholder Result
	tr := NewTracer(conf)
	results, err := tr.Run()
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Hops) != 0 {
		t.Errorf("non-v6 target should yield no hops, got %d", len(results[0].Hops))
	}
}
