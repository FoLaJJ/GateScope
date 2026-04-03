package l2

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/AutoScan/agentscan/internal/scanner"
	"github.com/hashicorp/mdns"
)

const openClawService = "_openclaw-gw._tcp"

type MDNSProber struct {
	Timeout time.Duration
}

func NewMDNSProber(timeout time.Duration) *MDNSProber {
	return &MDNSProber{Timeout: timeout}
}

type MDNSEntry struct {
	Host    string
	IP      string
	Port    int
	Version string
	AgentID string
	Info    []string
}

func (p *MDNSProber) Browse() ([]MDNSEntry, scanner.ProbeResult) {
	start := time.Now()
	result := scanner.ProbeResult{
		Type:    "mdns_browse",
		Details: make(map[string]string),
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	entriesCh := make(chan *mdns.ServiceEntry, 16)
	var entries []MDNSEntry

	go func() {
		for entry := range entriesCh {
			e := MDNSEntry{
				Host: entry.Host,
				Port: entry.Port,
				Info: entry.InfoFields,
			}
			if entry.AddrV4 != nil {
				e.IP = entry.AddrV4.String()
			} else if entry.AddrV6 != nil {
				e.IP = entry.AddrV6.String()
			}
			for _, info := range entry.InfoFields {
				if len(info) > 8 && info[:8] == "version=" {
					e.Version = info[8:]
				}
				if len(info) > 3 && info[:3] == "id=" {
					e.AgentID = info[3:]
				}
			}
			entries = append(entries, e)
		}
	}()

	params := &mdns.QueryParam{
		Service:             openClawService,
		Domain:              "local",
		Entries:             entriesCh,
		Timeout:             p.Timeout,
		DisableIPv6:         false,
		WantUnicastResponse: false,
	}

	origOutput := log.Writer()
	log.SetOutput(io.Discard)
	err := mdns.Query(params)
	log.SetOutput(origOutput)
	<-ctx.Done()
	close(entriesCh)

	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return entries, result
	}

	result.Success = true
	if len(entries) > 0 {
		result.Matched = true
		result.Details["agent_type"] = "openclaw"
		result.Details["count"] = fmt.Sprintf("%d", len(entries))
		if entries[0].Version != "" {
			result.Details["version"] = entries[0].Version
		}
	}

	return entries, result
}

func (p *MDNSProber) ProbeTarget(ip string, port int) scanner.ProbeResult {
	entries, result := p.Browse()
	for _, e := range entries {
		if e.IP == ip && (port == 0 || e.Port == port) {
			result.Matched = true
			result.Details["agent_type"] = "openclaw"
			if e.Version != "" {
				result.Details["version"] = e.Version
			}
			if e.AgentID != "" {
				result.Details["agent_id"] = e.AgentID
			}
			result.Details["mdns_host"] = e.Host
			break
		}
	}
	return result
}
