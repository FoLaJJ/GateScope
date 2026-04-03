package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/scanner"
	"github.com/AutoScan/agentscan/internal/scanner/l1"
	"github.com/AutoScan/agentscan/internal/scanner/l2"
	"github.com/AutoScan/agentscan/internal/scanner/l3"
	"github.com/AutoScan/agentscan/internal/utils/iputil"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PipelineConfig struct {
	Ports       []int
	ScanDepth   models.ScanDepth
	Timeout     time.Duration
	Concurrency int
	RateLimit   int
	L1ScanMode  string
	EnableMDNS  bool
	MDNSTimeout time.Duration
	EnablePoC   bool
	TaskID      string
}

type PipelineResult struct {
	Assets          []models.Asset
	Vulnerabilities []models.Vulnerability
	OpenPorts       int
	TotalScanned    int
}

type ProgressCallback func(scanned, total int, phase string)

type Pipeline struct {
	bus        eventbus.EventBus
	onProgress ProgressCallback
}

type portScanner interface {
	ScanPorts(ip string, ports []int) []scanner.PortResult
}

type endpoint struct {
	ip   string
	port int
}

type indexedEndpoint struct {
	index    int
	endpoint endpoint
}

type l2Outcome struct {
	index           int
	asset           *models.Asset
	vulnerabilities []models.Vulnerability
}

type endpointRateLimiter struct {
	interval time.Duration
	next     time.Time
}

var newTCPScanner = func(timeout time.Duration, concurrency int) portScanner {
	return l1.NewTCPScanner(timeout, concurrency)
}

var newSYNScanner = func(timeout time.Duration, concurrency int) (portScanner, error) {
	return l1.NewSYNScanner(timeout, concurrency)
}

func NewPipeline(bus eventbus.EventBus) *Pipeline {
	return &Pipeline{bus: bus}
}

func (p *Pipeline) SetProgressCallback(cb ProgressCallback) {
	p.onProgress = cb
}

func (p *Pipeline) Run(ctx context.Context, targets string, cfg PipelineConfig) (*PipelineResult, error) {
	ips, err := iputil.ParseTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("parse targets: %w", err)
	}

	result := &PipelineResult{TotalScanned: len(ips)}
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = []int{18789, 18792, 3000, 8080, 8888}
	}
	concurrency := normalizedConcurrency(cfg.Concurrency)

	// --- L1: Port Discovery ---
	var scannedCount int64
	l1Scanner := p.newL1Scanner(cfg.Timeout, concurrency, cfg.L1ScanMode)
	var openPorts []scanner.PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var cancelled bool

	for _, ip := range ips {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			results := l1Scanner.ScanPorts(ip, ports)
			var found []scanner.PortResult
			for _, r := range results {
				if r.Open {
					found = append(found, r)
				}
			}
			if len(found) > 0 {
				mu.Lock()
				openPorts = append(openPorts, found...)
				mu.Unlock()

				if p.bus != nil {
					p.bus.Publish(ctx, eventbus.Event{
						Topic:   eventbus.TopicPortDiscovered,
						Payload: found,
					})
				}
			}

			n := atomic.AddInt64(&scannedCount, 1)
			if p.onProgress != nil {
				p.onProgress(int(n), len(ips), "l1")
			}
		}(ip)
	}
	wg.Wait()
	result.OpenPorts = len(openPorts)

	if cancelled {
		return result, ctx.Err()
	}

	if cfg.ScanDepth == models.ScanDepthL1 || len(openPorts) == 0 {
		return result, nil
	}

	// --- mDNS Discovery ---
	mdnsEntries := make(map[string]l2.MDNSEntry)
	if cfg.EnableMDNS {
		mdnsTimeout := cfg.MDNSTimeout
		if mdnsTimeout == 0 {
			mdnsTimeout = 5 * time.Second
		}
		prober := l2.NewMDNSProber(mdnsTimeout)
		entries, _ := prober.Browse()
		for _, e := range entries {
			mdnsEntries[e.IP] = e
		}
	}

	// --- L2: Fingerprinting ---
	seen := make(map[endpoint]bool)
	var l2Targets []endpoint
	for _, pr := range openPorts {
		ep := endpoint{pr.IP, pr.Port}
		if !seen[ep] {
			seen[ep] = true
			l2Targets = append(l2Targets, ep)
		}
	}
	for ip, e := range mdnsEntries {
		ep := endpoint{ip, e.Port}
		if !seen[ep] {
			seen[ep] = true
			l2Targets = append(l2Targets, ep)
		}
	}

	if err := p.runL2(ctx, l2Targets, mdnsEntries, cfg, result); err != nil {
		return result, err
	}

	return result, nil
}

func (p *Pipeline) newL1Scanner(timeout time.Duration, concurrency int, mode string) portScanner {
	if mode == "syn" {
		synScanner, err := newSYNScanner(timeout, concurrency)
		if err == nil {
			return synScanner
		}

		logger.Named("pipeline").Warn("syn scan unavailable, falling back to tcp connect",
			zap.String("mode", mode),
			zap.Error(err),
		)
	}

	return newTCPScanner(timeout, concurrency)
}

func (p *Pipeline) runL2(
	ctx context.Context,
	l2Targets []endpoint,
	mdnsEntries map[string]l2.MDNSEntry,
	cfg PipelineConfig,
	result *PipelineResult,
) error {
	if len(l2Targets) == 0 {
		return nil
	}

	httpProber := l2.NewHTTPProber(cfg.Timeout)
	wsProber := l2.NewWSProber(cfg.Timeout)
	workerCount := normalizedConcurrency(cfg.Concurrency)
	if workerCount > len(l2Targets) {
		workerCount = len(l2Targets)
	}

	jobs := make(chan indexedEndpoint)
	outcomes := make(chan l2Outcome, len(l2Targets))
	var wg sync.WaitGroup
	var completed int64

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for job := range jobs {
				outcomes <- p.processL2Target(ctx, job, httpProber, wsProber, mdnsEntries, cfg, len(l2Targets), &completed)
			}
		}()
	}

	limiter := newEndpointRateLimiter(cfg.RateLimit)
	cancelled := false
	for index, target := range l2Targets {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		if err := limiter.Wait(ctx); err != nil {
			cancelled = true
			break
		}

		select {
		case <-ctx.Done():
			cancelled = true
		case jobs <- indexedEndpoint{index: index, endpoint: target}:
		}

		if cancelled {
			break
		}
	}

	close(jobs)
	wg.Wait()
	close(outcomes)

	ordered := make([]l2Outcome, len(l2Targets))
	for outcome := range outcomes {
		ordered[outcome.index] = outcome
	}

	for _, outcome := range ordered {
		if outcome.asset == nil {
			continue
		}

		result.Assets = append(result.Assets, *outcome.asset)
		result.Vulnerabilities = append(result.Vulnerabilities, outcome.vulnerabilities...)
	}

	if cancelled || ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}

func (p *Pipeline) processL2Target(
	ctx context.Context,
	job indexedEndpoint,
	hp *l2.HTTPProber,
	wp *l2.WSProber,
	mdns map[string]l2.MDNSEntry,
	cfg PipelineConfig,
	total int,
	completed *int64,
) l2Outcome {
	agent := fingerprint(job.endpoint.ip, job.endpoint.port, hp, wp, mdns)
	outcome := l2Outcome{index: job.index}

	if agent.Score > 0 {
		asset := agentToAsset(agent, cfg.TaskID)
		outcome.asset = &asset

		if cfg.ScanDepth == models.ScanDepthL3 && agent.AgentType == "openclaw" {
			outcome.vulnerabilities = p.validateL3(asset, agent, cfg)
		}

		if p.bus != nil {
			p.bus.Publish(ctx, eventbus.Event{
				Topic:   eventbus.TopicAgentIdentified,
				Payload: asset,
			})
		}
	}

	n := atomic.AddInt64(completed, 1)
	if p.onProgress != nil {
		p.onProgress(int(n), total, "l2")
	}

	return outcome
}

func newEndpointRateLimiter(rate int) *endpointRateLimiter {
	if rate <= 0 {
		return nil
	}

	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	return &endpointRateLimiter{interval: interval}
}

func (l *endpointRateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}

	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}

	waitUntil := l.next
	l.next = l.next.Add(l.interval)
	wait := time.Until(waitUntil)
	if wait <= 0 {
		return nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func normalizedConcurrency(value int) int {
	if value < 1 {
		return 1
	}
	return value
}

func fingerprint(ip string, port int, hp *l2.HTTPProber, wp *l2.WSProber, mdns map[string]l2.MDNSEntry) scanner.AgentInfo {
	var probes []scanner.ProbeResult
	var score float64

	healthResult := hp.ProbeHealth(ip, port)
	probes = append(probes, healthResult)
	if healthResult.Matched {
		score += 30
	}

	htmlResult := hp.ProbeRootHTML(ip, port)
	probes = append(probes, htmlResult)
	if htmlResult.Matched {
		score += 20
	}

	configResult := hp.ProbeControlUIConfig(ip, port)
	probes = append(probes, configResult)
	if configResult.Matched {
		score += 20
	}

	wsResult := wp.Probe(ip, port)
	probes = append(probes, wsResult)
	if wsResult.Matched {
		score += 15
	}

	if entry, ok := mdns[ip]; ok {
		mdnsResult := scanner.ProbeResult{
			Type: "mdns", Success: true, Matched: true,
			Details: map[string]string{
				"agent_type": "openclaw",
				"version":    entry.Version,
				"agent_id":   entry.AgentID,
			},
		}
		probes = append(probes, mdnsResult)
		score += 15
	}

	if score > 100 {
		score = 100
	}

	agentType, ver, authMode, agentID := "unknown", "", "", ""
	for _, pr := range probes {
		if pr.Matched {
			if t, ok := pr.Details["agent_type"]; ok {
				agentType = t
			}
			if v, ok := pr.Details["version"]; ok && v != "" && ver == "" {
				ver = v
			}
			if a, ok := pr.Details["auth_mode"]; ok {
				authMode = a
			}
			if id, ok := pr.Details["agent_id"]; ok && id != "" && agentID == "" {
				agentID = id
			}
			if wa, ok := pr.Details["ws_auth"]; ok && authMode == "" {
				authMode = wa
			}
		}
	}

	return scanner.AgentInfo{
		IP: ip, Port: port,
		AgentType: agentType, Version: ver,
		AuthMode: authMode, AgentID: agentID,
		Probes: probes, Score: score,
	}
}

func (p *Pipeline) validateL3(asset models.Asset, agent scanner.AgentInfo, cfg PipelineConfig) []models.Vulnerability {
	input := l3.ValidationInput{
		IP: agent.IP, Port: agent.Port,
		AgentType: agent.AgentType, Version: agent.Version,
		AuthMode: agent.AuthMode, TaskID: cfg.TaskID, AssetID: asset.ID,
	}
	output := l3.Validate(input, l3.ValidatorConfig{Timeout: cfg.Timeout, EnablePoC: cfg.EnablePoC})

	if p.bus != nil {
		for _, v := range output.Vulnerabilities {
			p.bus.Publish(context.Background(), eventbus.Event{
				Topic:   eventbus.TopicVulnDetected,
				Payload: v,
			})
		}
	}

	return output.Vulnerabilities
}

func agentToAsset(agent scanner.AgentInfo, taskID string) models.Asset {
	probeMap := models.JSONMap{"probes": agent.Probes}

	meta := models.JSONMap{}
	for _, pr := range agent.Probes {
		if pr.Matched {
			for k, v := range pr.Details {
				if k != "agent_type" && k != "version" && k != "auth_mode" && k != "agent_id" {
					meta[k] = v
				}
			}
		}
	}

	return models.Asset{
		ID:           uuid.New().String(),
		TaskID:       taskID,
		IP:           agent.IP,
		Port:         agent.Port,
		AgentType:    agent.AgentType,
		Version:      agent.Version,
		AuthMode:     agent.AuthMode,
		AgentID:      agent.AgentID,
		Confidence:   agent.Score,
		RiskLevel:    models.RiskFromAuthMode(agent.AuthMode),
		Status:       models.AssetStatusActive,
		ProbeDetails: probeMap,
		Metadata:     meta,
	}
}
