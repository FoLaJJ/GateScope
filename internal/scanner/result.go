package scanner

import "time"

type PortResult struct {
	IP   string
	Port int
	Open bool
}

type AgentInfo struct {
	IP        string
	Port      int
	AgentType string // "openclaw", "clawhive", "unknown" ...
	Version   string
	AuthMode  string // "none", "token", "oauth"
	AgentID   string
	RawHealth map[string]any
	Probes    []ProbeResult
	Score     float64 // 0-100 confidence
}

type ProbeResult struct {
	Type      string // "http_health", "websocket", "mdns"
	Success   bool
	Matched   bool
	Details   map[string]string
	Duration  time.Duration
	Error     string
}
