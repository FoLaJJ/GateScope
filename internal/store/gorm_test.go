package store

import (
	"context"
	"testing"
	"time"

	"github.com/AutoScan/agentscan/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T) Store {
	s, err := NewGormStoreSimple("sqlite", ":memory:")
	require.NoError(t, err)
	require.NoError(t, s.AutoMigrate())
	return s
}

func TestTaskCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	task := &models.Task{
		ID:      uuid.New().String(),
		Name:    "test-scan",
		Targets: "192.168.1.0/24",
		Status:  models.TaskStatusPending,
		Type:    models.TaskTypeInstant,
	}

	err := s.CreateTask(ctx, task)
	assert.NoError(t, err)

	got, err := s.GetTask(ctx, task.ID)
	assert.NoError(t, err)
	assert.Equal(t, "test-scan", got.Name)
	assert.Equal(t, models.TaskStatusPending, got.Status)

	got.Status = models.TaskStatusRunning
	err = s.UpdateTask(ctx, got)
	assert.NoError(t, err)

	tasks, total, err := s.ListTasks(ctx, TaskFilter{})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, 1, len(tasks))

	err = s.DeleteTask(ctx, task.ID)
	assert.NoError(t, err)

	_, err = s.GetTask(ctx, task.ID)
	assert.Error(t, err)
}

func TestCreateTaskPersistsExplicitFalseEnableMDNS(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	task := &models.Task{
		ID:         uuid.New().String(),
		Name:       "mdns-off",
		Targets:    "192.168.1.1",
		Status:     models.TaskStatusPending,
		Type:       models.TaskTypeInstant,
		EnableMDNS: false,
	}

	require.NoError(t, s.CreateTask(ctx, task))

	got, err := s.GetTask(ctx, task.ID)
	require.NoError(t, err)
	assert.False(t, got.EnableMDNS)
}

func TestAssetUpsert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	asset := &models.Asset{
		ID:        uuid.New().String(),
		IP:        "192.168.1.1",
		Port:      18789,
		AgentType: "openclaw",
		Version:   "2026.3.13",
		RiskLevel: models.RiskCritical,
		Status:    models.AssetStatusActive,
	}

	err := s.UpsertAsset(ctx, asset)
	assert.NoError(t, err)

	asset2 := &models.Asset{
		ID:        uuid.New().String(),
		IP:        "192.168.1.1",
		Port:      18789,
		AgentType: "openclaw",
		Version:   "2026.3.14",
		RiskLevel: models.RiskLow,
		Status:    models.AssetStatusActive,
	}
	err = s.UpsertAsset(ctx, asset2)
	assert.NoError(t, err)

	assets, total, err := s.ListAssets(ctx, AssetFilter{})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "2026.3.14", assets[0].Version)
}

func TestVulnerabilities(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	vuln := &models.Vulnerability{
		ID:            uuid.New().String(),
		AssetID:       "asset-1",
		CVEID:         "CVE-2026-25253",
		CNNVDID:       "CNNVD-202604-123",
		GHSAID:        "GHSA-g8p2-7wf7-98mq",
		Title:         "WebSocket Hijack",
		DescriptionZH: "中文漏洞描述",
		Severity:      models.SeverityHigh,
		CVSS:          8.8,
	}

	err := s.CreateVulnerability(ctx, vuln)
	assert.NoError(t, err)

	vulns, total, err := s.ListVulnerabilities(ctx, VulnFilter{})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "CVE-2026-25253", vulns[0].CVEID)
	assert.Equal(t, "CNNVD-202604-123", vulns[0].CNNVDID)
	assert.Equal(t, "GHSA-g8p2-7wf7-98mq", vulns[0].GHSAID)
	assert.Equal(t, "中文漏洞描述", vulns[0].DescriptionZH)
}

func TestDashboardStats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	s.CreateTask(ctx, &models.Task{ID: uuid.New().String(), Name: "t1", Status: models.TaskStatusCompleted, Type: models.TaskTypeInstant, Targets: "x"})
	s.CreateAsset(ctx, &models.Asset{ID: uuid.New().String(), IP: "1.1.1.1", Port: 18789, RiskLevel: models.RiskCritical, AgentType: "openclaw", Status: models.AssetStatusActive})
	s.CreateVulnerability(ctx, &models.Vulnerability{ID: uuid.New().String(), AssetID: "a1", Title: "test", Severity: models.SeverityHigh})

	stats, err := s.GetDashboardStats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalTasks)
	assert.Equal(t, int64(1), stats.TotalAssets)
	assert.Equal(t, int64(1), stats.TotalVulns)
}

func TestUserAuth(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	user := &models.User{
		ID:       uuid.New().String(),
		Username: "admin",
		Password: "hashed",
		Role:     "admin",
	}

	err := s.CreateUser(ctx, user)
	assert.NoError(t, err)

	got, err := s.GetUserByUsername(ctx, "admin")
	assert.NoError(t, err)
	assert.Equal(t, "admin", got.Username)

	_, err = s.GetUserByUsername(ctx, "nonexist")
	assert.Error(t, err)
}

func TestDeleteTaskCascadesAssociatedData(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	taskID := uuid.New().String()
	assetID := uuid.New().String()

	require.NoError(t, s.CreateTask(ctx, &models.Task{
		ID:      taskID,
		Name:    "cascade-test",
		Targets: "127.0.0.1",
		Status:  models.TaskStatusCompleted,
		Type:    models.TaskTypeInstant,
	}))
	require.NoError(t, s.CreateAsset(ctx, &models.Asset{
		ID:        assetID,
		TaskID:    taskID,
		IP:        "127.0.0.1",
		Port:      8080,
		AgentType: "openclaw",
		RiskLevel: models.RiskHigh,
		Status:    models.AssetStatusActive,
	}))
	require.NoError(t, s.CreateVulnerability(ctx, &models.Vulnerability{
		ID:       uuid.New().String(),
		TaskID:   taskID,
		AssetID:  assetID,
		Title:    "test-vuln",
		Severity: models.SeverityHigh,
	}))
	require.NoError(t, s.CreateScanResult(ctx, &models.ScanResult{
		ID:      uuid.New().String(),
		TaskID:  taskID,
		IP:      "127.0.0.1",
		Port:    8080,
		Phase:   "l3",
		Success: true,
	}))
	require.NoError(t, s.CreateTaskEvent(ctx, &models.TaskEvent{
		ID:        uuid.New().String(),
		TaskID:    taskID,
		EventType: "task.completed",
		Summary:   "done",
	}))

	require.NoError(t, s.DeleteTask(ctx, taskID))

	assets, assetTotal, err := s.ListAssets(ctx, AssetFilter{TaskID: taskID})
	require.NoError(t, err)
	assert.Equal(t, int64(0), assetTotal)
	assert.Len(t, assets, 0)

	vulns, vulnTotal, err := s.ListVulnerabilities(ctx, VulnFilter{TaskID: taskID})
	require.NoError(t, err)
	assert.Equal(t, int64(0), vulnTotal)
	assert.Len(t, vulns, 0)

	results, err := s.ListScanResults(ctx, taskID)
	require.NoError(t, err)
	assert.Len(t, results, 0)

	events, err := s.ListTaskEvents(ctx, taskID, 10)
	require.NoError(t, err)
	assert.Len(t, events, 0)
}

func TestTaskEvents(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	taskID := uuid.New().String()

	require.NoError(t, s.CreateTask(ctx, &models.Task{
		ID:      taskID,
		Name:    "events-test",
		Targets: "127.0.0.1",
		Status:  models.TaskStatusCompleted,
		Type:    models.TaskTypeInstant,
	}))

	firstTime := time.Now().Add(-time.Minute)
	secondTime := time.Now()

	require.NoError(t, s.CreateTaskEvent(ctx, &models.TaskEvent{
		ID:        uuid.New().String(),
		TaskID:    taskID,
		EventType: "task.progress",
		Summary:   "progress",
		EventTime: firstTime,
	}))
	require.NoError(t, s.CreateTaskEvent(ctx, &models.TaskEvent{
		ID:        uuid.New().String(),
		TaskID:    taskID,
		EventType: "task.completed",
		Summary:   "completed",
		EventTime: secondTime,
	}))

	events, err := s.ListTaskEvents(ctx, taskID, 10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "task.completed", events[0].EventType)
	assert.Equal(t, "task.progress", events[1].EventType)
}
