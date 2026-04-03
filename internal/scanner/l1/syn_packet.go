package l1

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
)

type synResponse int

const (
	synResponseIgnore synResponse = iota
	synResponseOpen
	synResponseClosed
)

func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort int, seq uint32) ([]byte, error) {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return nil, fmt.Errorf("syn scan only supports ipv4")
	}

	packet := make([]byte, ipv4HeaderLen+tcpHeaderLen)
	ipHeader := packet[:ipv4HeaderLen]
	tcpHeader := packet[ipv4HeaderLen:]

	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(ipHeader[6:8], 0x4000)
	ipHeader[8] = 64
	ipHeader[9] = 6
	copy(ipHeader[12:16], src)
	copy(ipHeader[16:20], dst)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader))

	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = 0x02
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(src, dst, tcpHeader))

	return packet, nil
}

func classifySYNResponse(packet []byte, expectedSrcIP, expectedDstIP net.IP, expectedSrcPort, expectedDstPort int) synResponse {
	src := expectedSrcIP.To4()
	dst := expectedDstIP.To4()
	if src == nil || dst == nil {
		return synResponseIgnore
	}
	if len(packet) < ipv4HeaderLen+tcpHeaderLen || packet[9] != 6 {
		return synResponseIgnore
	}

	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < ipv4HeaderLen || len(packet) < headerLen+tcpHeaderLen {
		return synResponseIgnore
	}

	if !net.IP(packet[12:16]).Equal(src) || !net.IP(packet[16:20]).Equal(dst) {
		return synResponseIgnore
	}

	tcpHeader := packet[headerLen:]
	if int(binary.BigEndian.Uint16(tcpHeader[0:2])) != expectedSrcPort ||
		int(binary.BigEndian.Uint16(tcpHeader[2:4])) != expectedDstPort {
		return synResponseIgnore
	}

	flags := tcpHeader[13]
	if flags&0x12 == 0x12 {
		return synResponseOpen
	}
	if flags&0x04 != 0 {
		return synResponseClosed
	}

	return synResponseIgnore
}

func checksum(data []byte) uint16 {
	var sum uint32

	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP net.IP, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)

	return checksum(pseudo)
}
