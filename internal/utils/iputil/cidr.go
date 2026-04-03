package iputil

import (
	"encoding/binary"
	"fmt"
	"net"
)

func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		single := net.ParseIP(cidr)
		if single != nil {
			return []string{single.String()}, nil
		}
		return nil, fmt.Errorf("invalid target: %s", cidr)
	}

	var ips []string
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv6 not supported yet: %s", cidr)
	}

	mask := binary.BigEndian.Uint32(ipnet.Mask)
	start := binary.BigEndian.Uint32(ip4) & mask
	end := start | ^mask

	// skip network and broadcast for /31 and larger
	ones, _ := ipnet.Mask.Size()
	skipEndpoints := ones < 31

	for i := start; i <= end; i++ {
		if skipEndpoints && (i == start || i == end) {
			continue
		}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, i)
		ips = append(ips, net.IP(buf).String())
	}
	return ips, nil
}
