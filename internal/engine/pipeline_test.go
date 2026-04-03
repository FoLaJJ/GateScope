package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/scanner/l1"
	"github.com/AutoScan/agentscan/internal/scanner/l2"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waitForAtomic(t *testing.T, val *int64, expected int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(val) >= expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type mockOpenClawOptions struct {
	healthDelay   time.Duration
	onHealthStart func()
	onHealthDone  func()
}

func updateMaxInt64(target *int64, next int64) {
	for {
		current := atomic.LoadInt64(target)
		if next <= current {
			return
		}
		if atomic.CompareAndSwapInt64(target, current, next) {
			return
		}
	}
}

func startMockOpenClaw(t *testing.T) (int, func()) {
	t.Helper()
	return startMockOpenClawWithOptions(t, mockOpenClawOptions{})
}

func startMockOpenClawWithOptions(t *testing.T, opts mockOpenClawOptions) (int, func()) {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if opts.onHealthStart != nil {
			opts.onHealthStart()
		}
		if opts.onHealthDone != nil {
			defer opts.onHealthDone()
		}
		if opts.healthDelay > 0 {
			time.Sleep(opts.healthDelay)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "status": "live",
			"version": "2026.2.20", "agent_id": "test-agent-001",
			"auth_mode": "none", "tools_loaded": 5,
		})
	})

	mux.HandleFunc("/__openclaw/control-ui-config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"serverVersion": "2026.2.20",
			"assistantName": "Test Agent",
		})
	})

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	wsHandler := func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteJSON(map[string]any{
			"type": "event", "event": "connect.challenge",
			"payload": map[string]any{"nonce": "test-nonce", "ts": time.Now().UnixMilli()},
		})
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
			conn.WriteJSON(map[string]any{
				"type": "res", "ok": true,
				"payload": map[string]any{
					"type": "hello-ok", "protocol": 3,
					"policy": map[string]any{"tickIntervalMs": 15000},
				},
			})
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			wsHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>OpenClaw Control</title></head><body><openclaw-app></openclaw-app></body></html>`)
	})
	mux.HandleFunc("/ws", wsHandler)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port

	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	return port, func() {
		server.Close()
	}
}

func TestPipelineE2E_L2(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	bus := eventbus.NewLocal()
	var identifiedCount int64
	bus.Subscribe(eventbus.TopicAgentIdentified, func(_ context.Context, ev eventbus.Event) {
		atomic.AddInt64(&identifiedCount, 1)
	})

	pipeline := NewPipeline(bus)
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL2,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		EnableMDNS:  false,
		TaskID:      "test-task",
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.OpenPorts, "should find 1 open port")
	assert.Equal(t, 1, len(result.Assets), "should identify 1 agent")

	asset := result.Assets[0]
	assert.Equal(t, "openclaw", asset.AgentType)
	assert.Equal(t, "2026.2.20", asset.Version)
	assert.Greater(t, asset.Confidence, float64(30))

	waitForAtomic(t, &identifiedCount, 1, time.Second)
	assert.Equal(t, int64(1), atomic.LoadInt64(&identifiedCount))

	log.Printf("E2E L2: agent=%s ver=%s auth=%s confidence=%.0f%%",
		asset.AgentType, asset.Version, asset.AuthMode, asset.Confidence)
}

func TestPipelineE2E_L3WithVulns(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	bus := eventbus.NewLocal()
	var vulnCount int64
	bus.Subscribe(eventbus.TopicVulnDetected, func(_ context.Context, ev eventbus.Event) {
		atomic.AddInt64(&vulnCount, 1)
	})

	pipeline := NewPipeline(bus)
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL3,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		EnableMDNS:  false,
		TaskID:      "test-task",
	})

	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Assets))
	assert.Greater(t, len(result.Vulnerabilities), 0, "old version should have vulnerabilities")

	waitForAtomic(t, &vulnCount, 1, time.Second)
	assert.Greater(t, atomic.LoadInt64(&vulnCount), int64(0))

	var hasCVE, hasAuth bool
	for _, v := range result.Vulnerabilities {
		if v.CheckType == "cve_match" {
			hasCVE = true
		}
		if v.CheckType == "auth_check" {
			hasAuth = true
		}
	}
	assert.True(t, hasCVE, "should find CVE matches for version 2026.2.20")
	assert.True(t, hasAuth, "should detect no-auth vulnerability")

	log.Printf("E2E L3: %d vulns found (%d events)", len(result.Vulnerabilities), atomic.LoadInt64(&vulnCount))
	for _, v := range result.Vulnerabilities {
		log.Printf("  - [%s] %s %s (CVSS %.1f)", v.Severity, v.CVEID, v.Title, v.CVSS)
	}
}

func TestPipelineE2E_L3PoCPrioritizesOverCVEMatch(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL3,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		EnableMDNS:  false,
		EnablePoC:   true,
		TaskID:      "test-task",
	})

	require.NoError(t, err)

	var hits []models.Vulnerability
	for _, v := range result.Vulnerabilities {
		if v.CVEID == "CVE-2026-25253" {
			hits = append(hits, v)
		}
	}

	require.Len(t, hits, 1)
	assert.Equal(t, "poc_verify", hits[0].CheckType)
	assert.Contains(t, hits[0].Title, "[PoC]")
}

func TestPipelineL1Only(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL1,
		Timeout:     3 * time.Second,
		Concurrency: 10,
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.OpenPorts)
	assert.Equal(t, 0, len(result.Assets), "L1 only should not fingerprint")
}

func TestPipelineL2Concurrency(t *testing.T) {
	var inFlight int64
	var maxInFlight int64

	ports := make([]int, 0, 4)
	cleanups := make([]func(), 0, 4)
	for range 4 {
		port, cleanup := startMockOpenClawWithOptions(t, mockOpenClawOptions{
			healthDelay: 150 * time.Millisecond,
			onHealthStart: func() {
				current := atomic.AddInt64(&inFlight, 1)
				updateMaxInt64(&maxInFlight, current)
			},
			onHealthDone: func() {
				atomic.AddInt64(&inFlight, -1)
			},
		})
		ports = append(ports, port)
		cleanups = append(cleanups, cleanup)
	}
	for _, cleanup := range cleanups {
		defer cleanup()
	}
	time.Sleep(100 * time.Millisecond)

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       ports,
		ScanDepth:   models.ScanDepthL2,
		Timeout:     2 * time.Second,
		Concurrency: 3,
		EnableMDNS:  false,
		TaskID:      "test-task",
	})

	require.NoError(t, err)
	assert.Len(t, result.Assets, len(ports))
	assert.Greater(t, atomic.LoadInt64(&maxInFlight), int64(1))
	assert.LessOrEqual(t, atomic.LoadInt64(&maxInFlight), int64(3))
}

func TestPipelineL2RateLimit(t *testing.T) {
	var (
		mu         sync.Mutex
		startTimes []time.Time
	)

	ports := make([]int, 0, 2)
	cleanups := make([]func(), 0, 2)
	for range 2 {
		port, cleanup := startMockOpenClawWithOptions(t, mockOpenClawOptions{
			healthDelay: 100 * time.Millisecond,
			onHealthStart: func() {
				mu.Lock()
				startTimes = append(startTimes, time.Now())
				mu.Unlock()
			},
		})
		ports = append(ports, port)
		cleanups = append(cleanups, cleanup)
	}
	for _, cleanup := range cleanups {
		defer cleanup()
	}
	time.Sleep(100 * time.Millisecond)

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       ports,
		ScanDepth:   models.ScanDepthL2,
		Timeout:     2 * time.Second,
		Concurrency: 4,
		RateLimit:   2,
		EnableMDNS:  false,
		TaskID:      "test-task",
	})

	require.NoError(t, err)
	require.Len(t, result.Assets, len(ports))
	require.Len(t, startTimes, len(ports))
	assert.GreaterOrEqual(t, startTimes[1].Sub(startTimes[0]), 350*time.Millisecond)
}

func TestPipelineL2CancellationStopsDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var started int64
	var cancelOnce sync.Once

	ports := make([]int, 0, 3)
	cleanups := make([]func(), 0, 3)
	for range 3 {
		port, cleanup := startMockOpenClawWithOptions(t, mockOpenClawOptions{
			healthDelay: 150 * time.Millisecond,
			onHealthStart: func() {
				atomic.AddInt64(&started, 1)
				cancelOnce.Do(cancel)
			},
		})
		ports = append(ports, port)
		cleanups = append(cleanups, cleanup)
	}
	for _, cleanup := range cleanups {
		defer cleanup()
	}
	time.Sleep(100 * time.Millisecond)

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(ctx, "127.0.0.1", PipelineConfig{
		Ports:       ports,
		ScanDepth:   models.ScanDepthL2,
		Timeout:     2 * time.Second,
		Concurrency: 4,
		RateLimit:   1,
		EnableMDNS:  false,
		TaskID:      "test-task",
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int64(1), atomic.LoadInt64(&started))
	assert.Len(t, result.Assets, 1)
}

func TestPipelineL1ScanModeConnectUsesTCPScanner(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	originalTCPFactory := newTCPScanner
	originalSYNFactory := newSYNScanner
	t.Cleanup(func() {
		newTCPScanner = originalTCPFactory
		newSYNScanner = originalSYNFactory
	})

	var tcpCalls int64
	newTCPScanner = func(timeout time.Duration, concurrency int) portScanner {
		atomic.AddInt64(&tcpCalls, 1)
		return l1.NewTCPScanner(timeout, concurrency)
	}
	newSYNScanner = func(timeout time.Duration, concurrency int) (portScanner, error) {
		t.Fatalf("syn scanner should not be constructed for connect mode")
		return nil, nil
	}

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL1,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		L1ScanMode:  "connect",
	})

	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(&tcpCalls))
	assert.Equal(t, 1, result.OpenPorts)
}

func TestPipelineL1ScanModeSynFallsBackToConnect(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	originalTCPFactory := newTCPScanner
	originalSYNFactory := newSYNScanner
	t.Cleanup(func() {
		newTCPScanner = originalTCPFactory
		newSYNScanner = originalSYNFactory
	})

	var synCalls int64
	newSYNScanner = func(timeout time.Duration, concurrency int) (portScanner, error) {
		atomic.AddInt64(&synCalls, 1)
		return nil, errors.New("raw sockets unavailable")
	}

	pipeline := NewPipeline(eventbus.NewLocal())
	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL1,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		L1ScanMode:  "syn",
	})

	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(&synCalls))
	assert.Equal(t, 1, result.OpenPorts)
}

func TestPipelineMDNSIgnoresEntriesOutsideExplicitTargets(t *testing.T) {
	port, cleanup := startMockOpenClaw(t)
	defer cleanup()
	time.Sleep(100 * time.Millisecond)

	originalBrowse := browseMDNSEntries
	t.Cleanup(func() {
		browseMDNSEntries = originalBrowse
	})
	browseMDNSEntries = func(timeout time.Duration) []l2.MDNSEntry {
		return []l2.MDNSEntry{
			{IP: "127.0.0.1", Port: port, Version: "2026.2.20", AgentID: "test-agent-001"},
			{IP: "192.168.79.134", Port: 18789, Version: "2026.3.13", AgentID: "main"},
		}
	}

	var (
		mu         sync.Mutex
		phaseTotal = map[string]int{}
	)

	pipeline := NewPipeline(eventbus.NewLocal())
	pipeline.SetProgressCallback(func(scanned, total int, phase string) {
		mu.Lock()
		defer mu.Unlock()
		if total > phaseTotal[phase] {
			phaseTotal[phase] = total
		}
	})

	result, err := pipeline.Run(context.Background(), "127.0.0.1", PipelineConfig{
		Ports:       []int{port},
		ScanDepth:   models.ScanDepthL2,
		Timeout:     3 * time.Second,
		Concurrency: 10,
		EnableMDNS:  true,
		TaskID:      "test-task",
	})

	require.NoError(t, err)
	require.Len(t, result.Assets, 1)
	assert.Equal(t, "127.0.0.1", result.Assets[0].IP)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, phaseTotal["l2"])
}
