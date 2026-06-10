package config

import (
	"testing"
)

func TestValidateRole(t *testing.T) {
	cfg := &Config{Role: "invalid"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestValidateBoth(t *testing.T) {
	cfg := &Config{
		Role:           RoleBoth,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error for role both: %v", err)
	}
}

func TestValidateClientMissingGPUAddrs(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing local_gpu_addrs")
	}
}

func TestValidateClientMismatchedGPUCount(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1", "10.0.0.2"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for mismatched GPU count")
	}
}

func TestValidateClientInvalidGPUAddr(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"not-an-ip"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid GPU addr")
	}
}

func TestValidateServerMissingGPUAddrs(t *testing.T) {
	cfg := &Config{
		Role:           RoleServer,
		LocalGPUAddrs:  []string{},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing server local_gpu_addrs")
	}
}

func TestValidateValidClient(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientPortRange.Min != 43600 || cfg.ClientPortRange.Max != 43699 {
		t.Fatalf("unexpected default client port range: %v", cfg.ClientPortRange)
	}
	if cfg.ServerPortRange.Min != 43600 || cfg.ServerPortRange.Max != 43609 {
		t.Fatalf("unexpected default server port range: %v", cfg.ServerPortRange)
	}
	if cfg.RateInSpan != 5000 {
		t.Fatalf("unexpected default rate: %d", cfg.RateInSpan)
	}
	if cfg.Span.String() != "1s" {
		t.Fatalf("unexpected default span: %v", cfg.Span)
	}
	if cfg.Delay.String() != "3s" {
		t.Fatalf("unexpected default delay: %v", cfg.Delay)
	}
	if cfg.MsgLen != 1024 {
		t.Fatalf("unexpected default msg_len: %d", cfg.MsgLen)
	}
}

func TestValidateCustomPortRange(t *testing.T) {
	cfg := &Config{
		Role:               RoleClient,
		LocalGPUAddrs:      []string{"10.0.0.1"},
		RemoteGPUAddrs:     []string{"10.0.1.1"},
		ClientPortRangeStr: "50000,50100",
		ServerPortRangeStr: "50000,50010",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientPortRange.Min != 50000 || cfg.ClientPortRange.Max != 50100 {
		t.Fatalf("unexpected client port range: %v", cfg.ClientPortRange)
	}
	if cfg.ServerPortRange.Min != 50000 || cfg.ServerPortRange.Max != 50010 {
		t.Fatalf("unexpected server port range: %v", cfg.ServerPortRange)
	}
}

func TestGPUPairCount(t *testing.T) {
	cfg := &Config{LocalGPUAddrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}}
	if n := cfg.GPUPairCount(); n != 3 {
		t.Fatalf("expected 3, got %d", n)
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input   string
		wantMin int
		wantMax int
		wantErr bool
	}{
		{"43600,43699", 43600, 43699, false},
		{" 43600 , 43699 ", 43600, 43699, false},
		{"43699,43600", 0, 0, true},
		{"43600", 0, 0, true},
		{"0,70000", 0, 0, true},
		{"abc,def", 0, 0, true},
	}
	for _, tt := range tests {
		pr, err := ParsePortRange(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if pr.Min != tt.wantMin || pr.Max != tt.wantMax {
			t.Errorf("ParsePortRange(%q) = {%d,%d}, want {%d,%d}", tt.input, pr.Min, pr.Max, tt.wantMin, tt.wantMax)
		}
	}
}

func TestGetNextPorts(t *testing.T) {
	cr := PortRange{Min: 100, Max: 102}
	sr := PortRange{Min: 200, Max: 202}

	cp, sp := uint16(100), uint16(200)
	cp, sp = GetNextPorts(cp, sp, cr, sr)
	if cp != 100 || sp != 201 {
		t.Fatalf("expected (100,201), got (%d,%d)", cp, sp)
	}

	cp, sp = GetNextPorts(100, 202, cr, sr)
	if cp != 101 || sp != 200 {
		t.Fatalf("expected (101,200) on server wrap, got (%d,%d)", cp, sp)
	}

	cp, sp = GetNextPorts(102, 202, cr, sr)
	if cp != 100 || sp != 200 {
		t.Fatalf("expected (100,200) on both wrap, got (%d,%d)", cp, sp)
	}
}
