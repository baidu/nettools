package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/baidu/nettools/stat"
)

type Role string

const (
	RoleServer Role = "server"
	RoleClient Role = "client"
	RoleBoth   Role = "both"
)

type PortRange = stat.PortRange

func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return PortRange{}, fmt.Errorf("invalid port range %q: expected min,max", s)
	}
	portMin, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid min port in %q: %w", s, err)
	}
	portMax, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid max port in %q: %w", s, err)
	}
	if portMin > portMax {
		return PortRange{}, fmt.Errorf("invalid port range %q: min > max", s)
	}
	if portMin < 1 || portMax > 65535 {
		return PortRange{}, fmt.Errorf("invalid port range %q: ports must be between 1 and 65535", s)
	}
	return PortRange{Min: portMin, Max: portMax}, nil
}

type Config struct {
	PprofAddr     string `json:"pprof_addr"`
	LogDir        string `json:"log_dir"`
	LogMaxAgeDays int    `json:"log_max_age_days"`

	Role Role `json:"role"`

	LocalGPUAddrs  []string `json:"local_gpu_addrs"`
	RemoteGPUAddrs []string `json:"remote_gpu_addrs"`

	TOS             int       `json:"tos"`
	ClientPortRange PortRange `json:"-"`
	ServerPortRange PortRange `json:"-"`

	ClientPortRangeStr string `json:"client_port_range"`
	ServerPortRangeStr string `json:"server_port_range"`

	RateInSpan   int64         `json:"rate_in_span"`
	Span         time.Duration `json:"-"`
	SpanStr      string        `json:"span"`
	Delay        time.Duration `json:"-"`
	DelayStr     string        `json:"delay"`
	MsgLen       int           `json:"msg_len"`
	Count        int           `json:"count"`
	SendDuration time.Duration `json:"-"`
	SendDurStr   string        `json:"send_duration"`
	Verbose      bool          `json:"verbose"`
}

func (c *Config) Validate() error {
	if c.Role != RoleServer && c.Role != RoleClient && c.Role != RoleBoth {
		return fmt.Errorf("invalid role %q: must be %q, %q or %q", c.Role, RoleServer, RoleClient, RoleBoth)
	}

	needsClient := c.Role == RoleClient || c.Role == RoleBoth
	needsServer := c.Role == RoleServer || c.Role == RoleBoth

	if needsClient || needsServer {
		if len(c.LocalGPUAddrs) == 0 {
			return fmt.Errorf("local_gpu_addrs is required")
		}
		if len(c.RemoteGPUAddrs) == 0 {
			return fmt.Errorf("remote_gpu_addrs is required")
		}
		if len(c.LocalGPUAddrs) != len(c.RemoteGPUAddrs) {
			return fmt.Errorf("local_gpu_addrs (%d) and remote_gpu_addrs (%d) must have the same count",
				len(c.LocalGPUAddrs), len(c.RemoteGPUAddrs))
		}
		for i, addr := range c.LocalGPUAddrs {
			if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid local_gpu_addrs[%d] %q: not a valid IPv4 address", i, addr)
			}
		}
		for i, addr := range c.RemoteGPUAddrs {
			if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
				return fmt.Errorf("invalid remote_gpu_addrs[%d] %q: not a valid IPv4 address", i, addr)
			}
		}
	}

	if c.ClientPortRangeStr != "" {
		pr, err := ParsePortRange(c.ClientPortRangeStr)
		if err != nil {
			return fmt.Errorf("client_port_range: %w", err)
		}
		c.ClientPortRange = pr
	} else {
		c.ClientPortRange = PortRange{Min: 43600, Max: 43699}
	}

	if c.ServerPortRangeStr != "" {
		pr, err := ParsePortRange(c.ServerPortRangeStr)
		if err != nil {
			return fmt.Errorf("server_port_range: %w", err)
		}
		c.ServerPortRange = pr
	} else {
		c.ServerPortRange = PortRange{Min: 43600, Max: 43609}
	}

	if c.RateInSpan == 0 {
		c.RateInSpan = 5000
	}

	if c.SpanStr != "" {
		d, err := time.ParseDuration(c.SpanStr)
		if err != nil {
			return fmt.Errorf("invalid span %q: %w", c.SpanStr, err)
		}
		c.Span = d
	} else {
		c.Span = time.Second
	}

	if c.DelayStr != "" {
		d, err := time.ParseDuration(c.DelayStr)
		if err != nil {
			return fmt.Errorf("invalid delay %q: %w", c.DelayStr, err)
		}
		c.Delay = d
	} else {
		c.Delay = 3 * time.Second
	}

	if c.SendDurStr != "" {
		d, err := time.ParseDuration(c.SendDurStr)
		if err != nil {
			return fmt.Errorf("invalid send_duration %q: %w", c.SendDurStr, err)
		}
		c.SendDuration = d
	}

	if c.MsgLen <= 0 {
		c.MsgLen = 1024
	}

	return nil
}

func (c *Config) GPUPairCount() int {
	return len(c.LocalGPUAddrs)
}

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
