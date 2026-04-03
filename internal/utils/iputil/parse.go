package iputil

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func ParseTargets(raw string) ([]string, error) {
	var all []string
	for _, seg := range strings.Split(raw, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		ips, err := expandTarget(seg)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", seg, err)
		}
		all = append(all, ips...)
	}
	return all, nil
}

func expandTarget(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		return ExpandCIDR(target)
	}
	if strings.Contains(target, "-") {
		return expandRange(target)
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", target)
	}
	return []string{ip.String()}, nil
}

func expandRange(r string) ([]string, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", r)
	}
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", parts[0])
	}
	endPart := strings.TrimSpace(parts[1])
	var endIP net.IP
	if net.ParseIP(endPart) != nil {
		endIP = net.ParseIP(endPart)
	} else {
		base := startIP.To4()
		if base == nil {
			return nil, fmt.Errorf("IPv6 range not supported")
		}
		last := base[3]
		var end byte
		_, err := fmt.Sscanf(endPart, "%d", &end)
		if err != nil || end < last {
			return nil, fmt.Errorf("invalid range end: %s", endPart)
		}
		endIP = net.IPv4(base[0], base[1], base[2], end)
	}

	start4 := startIP.To4()
	end4 := endIP.To4()
	if start4 == nil || end4 == nil {
		return nil, fmt.Errorf("IPv6 range not supported")
	}

	var ips []string
	for i := ipToUint32(start4); i <= ipToUint32(end4); i++ {
		ips = append(ips, uint32ToIP(i).String())
	}
	return ips, nil
}

func LoadTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// CSV: take first column
		if idx := strings.IndexByte(line, ','); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		targets = append(targets, line)
	}
	return targets, scanner.Err()
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func CountTargets(raw string) int {
	ips, err := ParseTargets(raw)
	if err != nil {
		return 0
	}
	return len(ips)
}
