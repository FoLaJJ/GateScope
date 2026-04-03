package task

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AutoScan/agentscan/internal/core/config"
	"github.com/AutoScan/agentscan/internal/core/eventbus"
	"github.com/AutoScan/agentscan/internal/engine"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/AutoScan/agentscan/internal/utils/iputil"
	"github.com/google/uuid"
)

type Manager struct {
	store    store.Store
	bus      eventbus.EventBus
	cfg      *config.Config
	pipeline *engine.Pipeline

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

func NewManager(s store.Store, bus eventbus.EventBus, cfg *config.Config) *Manager {
	return &Manager{
		store:    s,
		bus:      bus,
		cfg:      cfg,
		pipeline: engine.NewPipeline(bus),
		running:  make(map[string]context.CancelFunc),
	}
}

func (m *Manager) Create(ctx context.Context, t *models.Task) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.Status = models.TaskStatusPending
	t.TotalTargets = iputil.CountTargets(t.Targets)

	if t.Ports == "" {
		ports := make([]string, len(m.cfg.Scanner.DefaultPorts))
		for i, p := range m.cfg.Scanner.DefaultPorts {
			ports[i] = strconv.Itoa(p)
		}
		t.Ports = strings.Join(ports, ",")
	}
	if t.Concurrency == 0 {
		t.Concurrency = m.cfg.Scanner.Concurrency
	}
	if t.RateLimit == 0 {
		t.RateLimit = m.cfg.Scanner.RateLimit
	}
	if t.Timeout == 0 {
		t.Timeout = int(m.cfg.Scanner.Timeout.Seconds())
	}

	return m.store.CreateTask(ctx, t)
}

func (m *Manager) Get(ctx context.Context, id string) (*models.Task, error) {
	return m.store.GetTask(ctx, id)
}

func (m *Manager) List(ctx context.Context, filter store.TaskFilter) ([]models.Task, int64, error) {
	return m.store.ListTasks(ctx, filter)
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	m.Stop(id)
	return m.store.DeleteTask(ctx, id)
}

func (m *Manager) Start(ctx context.Context, id string) error {
	m.mu.Lock()
	if _, running := m.running[id]; running {
		m.mu.Unlock()
		return fmt.Errorf("task already running")
	}

	task, err := m.store.GetTask(ctx, id)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("get task: %w", err)
	}
	if task.Status == models.TaskStatusRunning {
		m.mu.Unlock()
		return fmt.Errorf("task already running")
	}

	taskCtx, cancel := context.WithCancel(context.Background())
	m.running[id] = cancel
	m.mu.Unlock()

	now := time.Now()
	task.Status = models.TaskStatusRunning
	task.StartedAt = &now
	task.ErrorMessage = ""
	m.store.UpdateTask(ctx, task)

	go m.execute(taskCtx, task)
	return nil
}

func (m *Manager) Stop(id string) {
	m.mu.Lock()
	if cancel, ok := m.running[id]; ok {
		cancel()
		delete(m.running, id)
	}
	m.mu.Unlock()
}

func (m *Manager) execute(ctx context.Context, task *models.Task) {
	defer func() {
		m.mu.Lock()
		delete(m.running, task.ID)
		m.mu.Unlock()
	}()

	ports := parsePorts(task.Ports)
	rateLimit := task.RateLimit
	if rateLimit == 0 {
		rateLimit = m.cfg.Scanner.RateLimit
	}
	pCfg := engine.PipelineConfig{
		Ports:       ports,
		ScanDepth:   task.ScanDepth,
		Timeout:     time.Duration(task.Timeout) * time.Second,
		Concurrency: task.Concurrency,
		RateLimit:   rateLimit,
		L1ScanMode:  m.cfg.Scanner.L1ScanMode,
		EnableMDNS:  task.EnableMDNS,
		MDNSTimeout: m.cfg.Scanner.MDNSTimeout,
		EnablePoC:   task.ScanDepth == models.ScanDepthL3,
		TaskID:      task.ID,
	}

	pipeline := engine.NewPipeline(m.bus)
	pipeline.SetProgressCallback(func(scanned, total int, phase string) {
		task.ScannedTargets = scanned
		if total > 0 {
			task.ProgressPercent = float64(scanned) / float64(total) * 100
		}
		m.store.UpdateTask(context.Background(), task)

		m.bus.Publish(ctx, eventbus.Event{
			Topic: eventbus.TopicTaskProgress,
			Payload: map[string]any{
				"task_id":  task.ID,
				"scanned":  scanned,
				"total":    total,
				"phase":    phase,
				"progress": task.ProgressPercent,
			},
		})
	})

	result, err := pipeline.Run(ctx, task.Targets, pCfg)

	now := time.Now()
	task.FinishedAt = &now
	if err != nil {
		if ctx.Err() != nil {
			task.Status = models.TaskStatusCancelled
			task.ErrorMessage = "task cancelled by user"
		} else {
			task.Status = models.TaskStatusFailed
			task.ErrorMessage = err.Error()
		}
	} else {
		task.Status = models.TaskStatusCompleted
		task.ProgressPercent = 100
	}

	if result != nil {
		task.OpenPorts = result.OpenPorts
		task.FoundAgents = len(result.Assets)
		task.FoundVulns = len(result.Vulnerabilities)

		bgCtx := context.Background()
		for i := range result.Assets {
			m.store.UpsertAsset(bgCtx, &result.Assets[i])
		}
		for i := range result.Vulnerabilities {
			m.store.CreateVulnerability(bgCtx, &result.Vulnerabilities[i])
		}
	}

	m.store.UpdateTask(context.Background(), task)
	m.bus.Publish(context.Background(), eventbus.Event{
		Topic:   eventbus.TopicTaskCompleted,
		Payload: task,
	})
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 && n <= 65535 {
			ports = append(ports, n)
		}
	}
	return ports
}
