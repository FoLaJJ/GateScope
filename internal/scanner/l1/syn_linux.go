//go:build linux

package l1

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
	"golang.org/x/sys/unix"
)

type SYNScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewSYNScanner(timeout time.Duration, concurrency int) (*SYNScanner, error) {
	if concurrency < 1 {
		concurrency = 1
	}

	scanner := &SYNScanner{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
	if err := scanner.checkAvailability(); err != nil {
		return nil, err
	}

	return scanner, nil
}

func (s *SYNScanner) ScanPorts(ip string, ports []int) []scanner.PortResult {
	var (
		results []scanner.PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, s.Concurrency)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := scanner.PortResult{IP: ip, Port: port, Open: s.scanPort(ip, port)}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}

func (s *SYNScanner) checkAvailability() error {
	sendFD, err := openRawSendSocket()
	if err != nil {
		return err
	}
	defer unix.Close(sendFD)

	recvFD, err := openRawRecvSocket(s.Timeout)
	if err != nil {
		return err
	}

	return unix.Close(recvFD)
}

func (s *SYNScanner) scanPort(ip string, port int) bool {
	dstIP := net.ParseIP(ip).To4()
	if dstIP == nil {
		return false
	}

	srcIP, err := discoverSourceIP(dstIP, port)
	if err != nil {
		return false
	}
	srcPort, err := randomSourcePort()
	if err != nil {
		return false
	}
	seq, err := randomUint32()
	if err != nil {
		return false
	}

	packet, err := buildSYNPacket(srcIP, dstIP, srcPort, port, seq)
	if err != nil {
		return false
	}

	recvFD, err := openRawRecvSocket(s.Timeout)
	if err != nil {
		return false
	}
	defer unix.Close(recvFD)

	sendFD, err := openRawSendSocket()
	if err != nil {
		return false
	}
	defer unix.Close(sendFD)

	var addr unix.SockaddrInet4
	copy(addr.Addr[:], dstIP)
	if err := unix.Sendto(sendFD, packet, 0, &addr); err != nil {
		return false
	}

	buffer := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(recvFD, buffer, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return false
			}
			return false
		}

		switch classifySYNResponse(buffer[:n], dstIP, srcIP, port, srcPort) {
		case synResponseOpen:
			return true
		case synResponseClosed:
			return false
		}
	}
}

func openRawSendSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("open raw send socket: %w", err)
	}

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("enable ip header include: %w", err)
	}

	return fd, nil
}

func openRawRecvSocket(timeout time.Duration) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("open raw recv socket: %w", err)
	}

	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set recv timeout: %w", err)
	}

	return fd, nil
}

func discoverSourceIP(dstIP net.IP, port int) (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dstIP, Port: port})
	if err != nil {
		return nil, fmt.Errorf("discover source ip: %w", err)
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return nil, fmt.Errorf("discover source ip: unexpected local addr")
	}

	srcIP := localAddr.IP.To4()
	if srcIP == nil {
		return nil, fmt.Errorf("discover source ip: non-ipv4 local addr")
	}

	return srcIP, nil
}

func randomSourcePort() (int, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("generate source port: %w", err)
	}

	return 32768 + int(binary.BigEndian.Uint16(raw[:])%28232), nil
}

func randomUint32() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("generate sequence: %w", err)
	}

	return binary.BigEndian.Uint32(raw[:]), nil
}
