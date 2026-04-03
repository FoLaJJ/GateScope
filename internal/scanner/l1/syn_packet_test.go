package l1

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChecksum(t *testing.T) {
	assert.Equal(t, uint16(0x1905), checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5}))
}

func TestBuildSYNPacket(t *testing.T) {
	srcIP := net.ParseIP("192.0.2.10")
	dstIP := net.ParseIP("198.51.100.20")

	packet, err := buildSYNPacket(srcIP, dstIP, 40000, 443, 0x12345678)
	require.NoError(t, err)
	require.Len(t, packet, ipv4HeaderLen+tcpHeaderLen)

	assert.Equal(t, byte(0x45), packet[0])
	assert.Equal(t, byte(6), packet[9])
	assert.Equal(t, uint16(ipv4HeaderLen+tcpHeaderLen), binary.BigEndian.Uint16(packet[2:4]))
	assert.Equal(t, uint16(40000), binary.BigEndian.Uint16(packet[ipv4HeaderLen:ipv4HeaderLen+2]))
	assert.Equal(t, uint16(443), binary.BigEndian.Uint16(packet[ipv4HeaderLen+2:ipv4HeaderLen+4]))
	assert.Equal(t, byte(0x02), packet[ipv4HeaderLen+13])
	assert.NotZero(t, binary.BigEndian.Uint16(packet[10:12]))
	assert.NotZero(t, binary.BigEndian.Uint16(packet[ipv4HeaderLen+16:ipv4HeaderLen+18]))
	assert.Zero(t, checksum(packet[:ipv4HeaderLen]))
	assert.Zero(t, tcpChecksum(srcIP, dstIP, packet[ipv4HeaderLen:]))
}

func TestClassifySYNResponse(t *testing.T) {
	srcIP := net.ParseIP("198.51.100.20")
	dstIP := net.ParseIP("192.0.2.10")

	openPacket, err := buildSYNPacket(srcIP, dstIP, 443, 40000, 0xabcdef)
	require.NoError(t, err)
	openPacket[ipv4HeaderLen+13] = 0x12
	binary.BigEndian.PutUint16(openPacket[ipv4HeaderLen+16:ipv4HeaderLen+18], 0)
	binary.BigEndian.PutUint16(
		openPacket[ipv4HeaderLen+16:ipv4HeaderLen+18],
		tcpChecksum(srcIP, dstIP, openPacket[ipv4HeaderLen:]),
	)

	closedPacket, err := buildSYNPacket(srcIP, dstIP, 443, 40000, 0xabcdef)
	require.NoError(t, err)
	closedPacket[ipv4HeaderLen+13] = 0x14
	binary.BigEndian.PutUint16(closedPacket[ipv4HeaderLen+16:ipv4HeaderLen+18], 0)
	binary.BigEndian.PutUint16(
		closedPacket[ipv4HeaderLen+16:ipv4HeaderLen+18],
		tcpChecksum(srcIP, dstIP, closedPacket[ipv4HeaderLen:]),
	)

	assert.Equal(t, synResponseOpen, classifySYNResponse(openPacket, srcIP, dstIP, 443, 40000))
	assert.Equal(t, synResponseClosed, classifySYNResponse(closedPacket, srcIP, dstIP, 443, 40000))
	assert.Equal(t, synResponseIgnore, classifySYNResponse(openPacket, srcIP, dstIP, 443, 40001))
}
