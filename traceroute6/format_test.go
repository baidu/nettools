package traceroute6

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/baidu/nettools/traceroute/enrich"
)

func TestFormatRTT(t *testing.T) {
	if got := formatRTT(1500 * time.Microsecond); got != "1.500ms" {
		t.Errorf("formatRTT = %q, want 1.500ms", got)
	}
}

func TestResultStringHeaderAndHops(t *testing.T) {
	r := &Result{
		Dst:     "ipv6.google.com",
		DstIP:   mustV6("2001:4860:4860::8888"),
		Proto:   ProtoICMP,
		MaxHops: 30,
		Hops: []Hop{
			{
				TTL:   1,
				Addrs: []net.IP{mustV6("2001:db8::1")},
				Hosts: []string{"gateway"},
				Probes: []ProbeResult{
					{FromIP: mustV6("2001:db8::1"), RTT: 1234 * time.Microsecond},
				},
			},
			{
				TTL:    2,
				Probes: []ProbeResult{{TimedOut: true}, {TimedOut: true}},
			},
		},
	}

	out := r.String()
	if !strings.HasPrefix(out, "traceroute6 to ipv6.google.com (2001:4860:4860::8888), 30 hops max, ICMPv6 probes") {
		t.Errorf("unexpected header: %q", out)
	}
	if !strings.Contains(out, "gateway (2001:db8::1)") {
		t.Errorf("expected hostname+ip, got: %q", out)
	}
	if !strings.Contains(out, "1.234ms") {
		t.Errorf("expected formatted RTT, got: %q", out)
	}
	if !strings.Contains(out, "2   * *") {
		t.Errorf("expected timeout stars for hop 2, got: %q", out)
	}
}

func TestResultStringECMP(t *testing.T) {
	r := &Result{
		Dst:     "x",
		DstIP:   mustV6("2001:db8::ff"),
		Proto:   ProtoUDP,
		MaxHops: 30,
		Hops: []Hop{{
			TTL:   5,
			Addrs: []net.IP{mustV6("2001:db8::a"), mustV6("2001:db8::b")},
			Hosts: []string{"", ""},
			Probes: []ProbeResult{
				{FromIP: mustV6("2001:db8::a"), RTT: time.Millisecond},
				{FromIP: mustV6("2001:db8::b"), RTT: 2 * time.Millisecond},
			},
		}},
	}
	out := r.String()
	if !strings.Contains(out, "(2001:db8::a)") || !strings.Contains(out, "(2001:db8::b)") {
		t.Errorf("expected both ECMP responders inline, got: %q", out)
	}
}

func TestResultStringWithEnrichment(t *testing.T) {
	r := &Result{
		Dst:     "dns.google",
		DstIP:   mustV6("2001:4860:4860::8888"),
		Proto:   ProtoICMP,
		MaxHops: 30,
		Hops: []Hop{{
			TTL:   1,
			Addrs: []net.IP{mustV6("2001:4860:4860::8888")},
			Hosts: []string{""},
			Infos: []*enrich.IPInfo{{
				IP: mustV6("2001:4860:4860::8888"), ASN: 15169, ASName: "GOOGLE",
				Prefix: "2001:4860::/32", Country: "US", City: "Mountain View",
			}},
			Probes: []ProbeResult{{FromIP: mustV6("2001:4860:4860::8888"), RTT: time.Millisecond}},
		}},
	}
	out := r.String()
	if !strings.Contains(out, "AS15169 GOOGLE 2001:4860::/32") {
		t.Errorf("missing ASN annotation: %q", out)
	}
	if !strings.Contains(out, "US Mountain View") {
		t.Errorf("missing geo annotation: %q", out)
	}
}

func TestFormatInfoEmpty(t *testing.T) {
	if got := formatInfo(nil); got != "" {
		t.Errorf("nil info should render empty, got %q", got)
	}
	if got := formatInfo(&enrich.IPInfo{}); got != "" {
		t.Errorf("empty info should render empty, got %q", got)
	}
}

func TestResultSummary(t *testing.T) {
	r := &Result{
		Hops: []Hop{{
			TTL:   1,
			Addrs: []net.IP{mustV6("2001:db8::1")},
			Probes: []ProbeResult{
				{RTT: 2 * time.Millisecond},
				{TimedOut: true},
			},
		}},
	}
	s := r.Summary()
	if !strings.Contains(s, "ttl=1") || !strings.Contains(s, "2001:db8::1") {
		t.Errorf("summary missing fields: %q", s)
	}
	if !strings.Contains(s, "loss=50%") {
		t.Errorf("summary loss wrong: %q", s)
	}
}
