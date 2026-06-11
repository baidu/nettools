package config

import (
	"reflect"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in      string
		want    Target
		wantErr bool
	}{
		{"10.0.0.1#192.168.0.1", Target{VTEPAddr: "10.0.0.1", EVRSrcAddr: "192.168.0.1"}, false},
		{"10.0.0.1#192.168.0.1#10.0.0.99", Target{VTEPAddr: "10.0.0.1", EVRSrcAddr: "192.168.0.1", MockSrcAddr: "10.0.0.99"}, false},
		{"  10.0.0.1#192.168.0.1  ", Target{VTEPAddr: "10.0.0.1", EVRSrcAddr: "192.168.0.1"}, false},
		{"10.0.0.1", Target{}, true},
		{"#192.168.0.1", Target{}, true},
		{"10.0.0.1#", Target{}, true},
		{"a#b#c#d", Target{}, true},
	}
	for _, tt := range tests {
		got, err := ParseTarget(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseTarget(%q) err=%v, wantErr=%v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets("10.0.0.1#192.168.0.1, 10.0.0.2#192.168.0.2#10.0.0.99")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	want := []Target{
		{VTEPAddr: "10.0.0.1", EVRSrcAddr: "192.168.0.1"},
		{VTEPAddr: "10.0.0.2", EVRSrcAddr: "192.168.0.2", MockSrcAddr: "10.0.0.99"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseTargets = %+v, want %+v", got, want)
	}

	if _, err := ParseTargets(""); err == nil {
		t.Error("ParseTargets('') should error")
	}
	if _, err := ParseTargets(",,"); err == nil {
		t.Error("ParseTargets(',,') should error")
	}
}

func TestTargetString(t *testing.T) {
	tests := []struct {
		t    Target
		want string
	}{
		{Target{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2"}, "1.1.1.1#2.2.2.2"},
		{Target{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2", MockSrcAddr: "3.3.3.3"}, "1.1.1.1#2.2.2.2#3.3.3.3"},
	}
	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	got, err := ParsePortRange("9000,9100")
	if err != nil || got.Min != 9000 || got.Max != 9100 {
		t.Errorf("ParsePortRange ok = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "9000", "9100,9000", "0,100", "1,70000", "abc,9000"} {
		if _, err := ParsePortRange(bad); err == nil {
			t.Errorf("ParsePortRange(%q) should error", bad)
		}
	}
}

func TestConfigValidateDefaults(t *testing.T) {
	c := &Config{
		ClientAddr: "10.0.0.1",
		Targets:    []Target{{VTEPAddr: "10.0.0.2", EVRSrcAddr: "192.168.0.1"}},
		MsgLen:     128,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.DstPort != 4789 {
		t.Errorf("DstPort default = %d, want 4789", c.DstPort)
	}
	if c.InnerDstPort != 8972 {
		t.Errorf("InnerDstPort default = %d, want 8972", c.InnerDstPort)
	}
	if c.SrcMAC == "" || c.DstMAC == "" {
		t.Errorf("MAC defaults not applied")
	}
	if c.VNI != 15990000 {
		t.Errorf("VNI default = %d, want 15990000", c.VNI)
	}
	if c.TTL != 64 {
		t.Errorf("TTL default = %d, want 64", c.TTL)
	}
	if c.Span != 100*time.Millisecond {
		t.Errorf("Span default = %v, want 100ms", c.Span)
	}
	if c.ClientPortRange.Min != 9981 || c.ClientPortRange.Max != 9981 {
		t.Errorf("ClientPortRange default = %+v", c.ClientPortRange)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		c    Config
	}{
		{"bad client addr", Config{ClientAddr: "not-an-ip", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2"}}, MsgLen: 64}},
		{"empty targets", Config{ClientAddr: "10.0.0.1", MsgLen: 64}},
		{"bad vtep", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "x", EVRSrcAddr: "2.2.2.2"}}, MsgLen: 64}},
		{"bad evr_src", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "x"}}, MsgLen: 64}},
		{"bad mock_src", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2", MockSrcAddr: "x"}}, MsgLen: 64}},
		{"vni too big", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2"}}, VNI: 1 << 24, MsgLen: 64}},
		{"missing msg_len", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2"}}}},
		{"bad src_mac", Config{ClientAddr: "10.0.0.1", Targets: []Target{{VTEPAddr: "1.1.1.1", EVRSrcAddr: "2.2.2.2"}}, SrcMAC: "zz", MsgLen: 64}},
	}
	for _, tt := range tests {
		c := tt.c
		if err := c.Validate(); err == nil {
			t.Errorf("%s: Validate() returned nil, want error", tt.name)
		}
	}
}

func TestGetNextPort(t *testing.T) {
	pr := PortRange{Min: 100, Max: 102}
	tests := []struct {
		in, want uint16
	}{
		{100, 101},
		{101, 102},
		{102, 100},
		{99, 100},  // below min wraps
		{200, 100}, // above max wraps
	}
	for _, tt := range tests {
		if got := GetNextPort(tt.in, pr); got != tt.want {
			t.Errorf("GetNextPort(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
