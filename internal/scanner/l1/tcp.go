package l1

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
)

type TCPScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewTCPScanner(timeout time.Duration, concurrency int) *TCPScanner {
	if concurrency < 1 {
		concurrency = 1
	}

	return &TCPScanner{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

func (s *TCPScanner) ScanPorts(ip string, ports []int) []scanner.PortResult {
	var (
		results []scanner.PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, s.Concurrency)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, s.Timeout)
			result := scanner.PortResult{IP: ip, Port: p, Open: err == nil}
			if err == nil {
				conn.Close()
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}
