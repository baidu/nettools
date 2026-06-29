package traceroute

import (
	"testing"
	"time"
)

func TestParseProtocol(t *testing.T) {
	cases := map[string]Protocol{
		"":     ProtoICMP,
		"icmp": ProtoICMP,
		"ICMP": ProtoICMP,
		"udp":  ProtoUDP,
		"UDP":  ProtoUDP,
		"tcp":  ProtoTCP,
		"TCP":  ProtoTCP,
	}
	for in, want := range cases {
		got, err := ParseProtocol(in)
		if err != nil {
			t.Fatalf("ParseProtocol(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseProtocol(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseProtocol("sctp"); err == nil {
		t.Errorf("ParseProtocol(sctp) expected error")
	}
}

func TestProtocolString(t *testing.T) {
	if ProtoICMP.String() != "ICMP" || ProtoUDP.String() != "UDP" || ProtoTCP.String() != "TCP" {
		t.Errorf("protocol String() mismatch: %s %s %s", ProtoICMP, ProtoUDP, ProtoTCP)
	}
}

func TestConfigValidate(t *testing.T) {
	base := func() *Config {
		c := DefaultConfig()
		c.Targets = []string{"1.2.3.4"}
		return c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no targets", func(c *Config) { c.Targets = nil }},
		{"max-hops too low", func(c *Config) { c.MaxHops = 0 }},
		{"max-hops too high", func(c *Config) { c.MaxHops = 256 }},
		{"queries zero", func(c *Config) { c.Queries = 0 }},
		{"timeout zero", func(c *Config) { c.Timeout = 0 }},
		{"parallel zero", func(c *Config) { c.Parallel = 0 }},
		{"tcp zero port", func(c *Config) { c.Protocol = ProtoTCP; c.Port = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestHopStats(t *testing.T) {
	h := Hop{TTL: 3}
	h.Probes = []ProbeResult{
		{RTT: 3 * time.Millisecond},
		{RTT: 1 * time.Millisecond},
		{TimedOut: true},
		{RTT: 2 * time.Millisecond},
	}

	if got := h.Received(); got != 3 {
		t.Errorf("Received = %d, want 3", got)
	}
	if got := h.LossRate(); got != 0.25 {
		t.Errorf("LossRate = %v, want 0.25", got)
	}
	if got := h.MinRTT(); got != time.Millisecond {
		t.Errorf("MinRTT = %v, want 1ms", got)
	}
	if got := h.MaxRTT(); got != 3*time.Millisecond {
		t.Errorf("MaxRTT = %v, want 3ms", got)
	}
	if got := h.AvgRTT(); got != 2*time.Millisecond {
		t.Errorf("AvgRTT = %v, want 2ms", got)
	}
}

func TestHopStatsEmpty(t *testing.T) {
	h := Hop{TTL: 1}
	h.Probes = []ProbeResult{{TimedOut: true}, {TimedOut: true}}
	if h.LossRate() != 1.0 {
		t.Errorf("LossRate = %v, want 1.0", h.LossRate())
	}
	if h.MinRTT() != 0 || h.AvgRTT() != 0 || h.MaxRTT() != 0 {
		t.Errorf("empty RTT stats should be zero")
	}
}

func TestHopAddAddrDedup(t *testing.T) {
	h := Hop{}
	h.addAddr(mustIP("10.0.0.1"))
	h.addAddr(mustIP("10.0.0.1"))
	h.addAddr(mustIP("10.0.0.2"))
	if len(h.Addrs) != 2 {
		t.Fatalf("expected 2 distinct addrs, got %d", len(h.Addrs))
	}
	if len(h.Hosts) != 2 {
		t.Fatalf("Hosts slice should track Addrs, got %d", len(h.Hosts))
	}
}

func TestHopReached(t *testing.T) {
	h := Hop{Probes: []ProbeResult{{TimedOut: true}, {Reached: true}}}
	if !h.Reached() {
		t.Errorf("expected hop reached")
	}
}
