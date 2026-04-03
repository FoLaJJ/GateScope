//go:build !linux

package l1

import (
	"fmt"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
)

type SYNScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewSYNScanner(timeout time.Duration, concurrency int) (*SYNScanner, error) {
	return nil, fmt.Errorf("syn scan is only supported on linux")
}

func (s *SYNScanner) ScanPorts(ip string, ports []int) []scanner.PortResult {
	return nil
}
