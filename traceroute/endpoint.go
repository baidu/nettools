package traceroute

import (
	"fmt"
	"net"
	"os"
)

// localEndpoint resolves the source IP and outbound interface for a destination.
// If conf.LocalAddr / conf.Interface are set they are validated and returned;
// otherwise they are auto-detected by consulting the routing table via a
// connect(2) on a UDP socket (no packets are sent).
func localEndpoint(conf *Config, dst net.IP) (srcIP net.IP, iface string, err error) {
	if conf.LocalAddr != "" {
		srcIP = net.ParseIP(conf.LocalAddr).To4()
		if srcIP == nil {
			return nil, "", fmt.Errorf("invalid local IPv4 address: %q", conf.LocalAddr)
		}
	} else {
		srcIP, err = outboundIP(dst)
		if err != nil {
			return nil, "", err
		}
	}

	iface = conf.Interface
	if iface == "" {
		iface = interfaceForIP(srcIP)
		if iface == "" {
			return nil, "", fmt.Errorf("cannot determine outbound interface for %s, use --interface/-I", srcIP)
		}
	}
	return srcIP, iface, nil
}

// outboundIP returns the local IPv4 the kernel would use to reach dst.
func outboundIP(dst net.IP) (net.IP, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "33434"))
	if err != nil {
		return nil, fmt.Errorf("resolve local IP for %s: %w", dst, err)
	}
	defer func() { _ = conn.Close() }()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if ip := ua.IP.To4(); ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 source address for %s", dst)
}

// interfaceForIP returns the name of the interface that owns ip.
func interfaceForIP(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return iface.Name
			}
		}
	}
	return ""
}

// pid returns the lower 16 bits of the process id, used to tag probes.
func pid() uint16 {
	return uint16(os.Getpid() & 0xFFFF)
}
