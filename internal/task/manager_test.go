package task

import (
	"context"
	"errors"
	"testing"

	"github.com/AutoScan/agentscan/internal/engine"
	"github.com/AutoScan/agentscan/internal/models"
	"github.com/AutoScan/agentscan/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubStore struct {
	upsertAsset         func(ctx context.Context, asset *models.Asset) error
	createVulnerability func(ctx context.Context, vuln *models.Vulnerability) error
	listAssets          func(ctx context.Context, filter store.AssetFilter) ([]models.Asset, int64, error)
	listVulnerabilities func(ctx context.Context, filter store.VulnFilter) ([]models.Vulnerability, int64, error)
	tasks               map[string]*models.Task
}

func (s *stubStore) CreateTask(_ context.Context, task *models.Task) error {
	if s.tasks != nil {
		copy := *task
		s.tasks[task.ID] = &copy
	}
	return nil
}
func (s *stubStore) GetTask(_ context.Context, id string) (*models.Task, error) {
	if s.tasks == nil {
		return nil, nil
	}
	task, ok := s.tasks[id]
	if !ok {
		return nil, errors.New("not found")
	}
	copy := *task
	return &copy, nil
}
func (s *stubStore) UpdateTask(_ context.Context, task *models.Task) error {
	if s.tasks != nil {
		copy := *task
		s.tasks[task.ID] = &copy
	}
	return nil
}
func (s *stubStore) DeleteTask(context.Context, string) error              { return nil }
func (s *stubStore) ListTasks(_ context.Context, filter store.TaskFilter) ([]models.Task, int64, error) {
	if s.tasks == nil {
		return nil, 0, nil
	}
	var tasks []models.Task
	for _, task := range s.tasks {
		if filter.Status != nil && task.Status != *filter.Status {
			continue
		}
		tasks = append(tasks, *task)
	}
	return tasks, int64(len(tasks)), nil
}
func (s *stubStore) CreateTaskEvent(context.Context, *models.TaskEvent) error { return nil }
func (s *stubStore) ListTaskEvents(context.Context, string, int) ([]models.TaskEvent, error) {
	return nil, nil
}
func (s *stubStore) CreateAsset(context.Context, *models.Asset) error        { return nil }
func (s *stubStore) GetAsset(context.Context, string) (*models.Asset, error) { return nil, nil }
func (s *stubStore) UpsertAsset(ctx context.Context, asset *models.Asset) error {
	if s.upsertAsset == nil {
		return nil
	}
	return s.upsertAsset(ctx, asset)
}
func (s *stubStore) ListAssets(ctx context.Context, filter store.AssetFilter) ([]models.Asset, int64, error) {
	if s.listAssets != nil {
		return s.listAssets(ctx, filter)
	}
	return nil, 0, nil
}
func (s *stubStore) CreateVulnerability(ctx context.Context, vuln *models.Vulnerability) error {
	if s.createVulnerability == nil {
		return nil
	}
	return s.createVulnerability(ctx, vuln)
}
func (s *stubStore) GetVulnerability(context.Context, string) (*models.Vulnerability, error) {
	return nil, nil
}
func (s *stubStore) ListVulnerabilities(ctx context.Context, filter store.VulnFilter) ([]models.Vulnerability, int64, error) {
	if s.listVulnerabilities != nil {
		return s.listVulnerabilities(ctx, filter)
	}
	return nil, 0, nil
}
func (s *stubStore) ListVulnsByAsset(context.Context, string) ([]models.Vulnerability, error) {
	return nil, nil
}
func (s *stubStore) CreateScanResult(context.Context, *models.ScanResult) error { return nil }
func (s *stubStore) ListScanResults(context.Context, string) ([]models.ScanResult, error) {
	return nil, nil
}
func (s *stubStore) GetUserByUsername(context.Context, string) (*models.User, error) { return nil, nil }
func (s *stubStore) CreateUser(context.Context, *models.User) error                  { return nil }
func (s *stubStore) GetDashboardStats(context.Context) (*store.DashboardStats, error) {
	return nil, nil
}
func (s *stubStore) AutoMigrate() error { return nil }
func (s *stubStore) Close() error       { return nil }

func TestPersistPipelineResultRemapsVulnerabilityAssetIDs(t *testing.T) {
	var created []models.Vulnerability

	s := &stubStore{
		upsertAsset: func(_ context.Context, asset *models.Asset) error {
			switch asset.IP {
			case "10.0.0.1":
				asset.ID = "existing-asset-id"
				return nil
			case "10.0.0.2":
				return errors.New("database is locked")
			default:
				return nil
			}
		},
		createVulnerability: func(_ context.Context, vuln *models.Vulnerability) error {
			created = append(created, *vuln)
			return nil
		},
	}

	mgr := &Manager{store: s}
	result := &engine.PipelineResult{
		Assets: []models.Asset{
			{ID: "asset-a", TaskID: "task-1", IP: "10.0.0.1", Port: 18789},
			{ID: "asset-b", TaskID: "task-1", IP: "10.0.0.2", Port: 18789},
		},
		Vulnerabilities: []models.Vulnerability{
			{ID: "vuln-a", TaskID: "task-1", AssetID: "asset-a", Title: "A", Severity: models.SeverityHigh},
			{ID: "vuln-b", TaskID: "task-1", AssetID: "asset-b", Title: "B", Severity: models.SeverityHigh},
		},
	}

	assetCount, vulnCount, err := mgr.persistPipelineResult(context.Background(), "task-1", result)
	require.Error(t, err)
	assert.Equal(t, 1, assetCount)
	assert.Equal(t, 1, vulnCount)
	require.Len(t, created, 1)
	assert.Equal(t, "existing-asset-id", created[0].AssetID)
	assert.Equal(t, "vuln-a", created[0].ID)
}

func TestStopMarksGhostRunningTaskCancelled(t *testing.T) {
	s := &stubStore{
		tasks: map[string]*models.Task{
			"task-1": {
				ID:     "task-1",
				Status: models.TaskStatusRunning,
			},
		},
	}

	mgr := &Manager{store: s, running: make(map[string]context.CancelFunc)}

	require.NoError(t, mgr.Stop(context.Background(), "task-1"))
	task, err := s.GetTask(context.Background(), "task-1")
	require.NoError(t, err)
	assert.Equal(t, models.TaskStatusCancelled, task.Status)
	assert.NotNil(t, task.FinishedAt)
	assert.Contains(t, task.ErrorMessage, "worker state was lost")
}

func TestRecoverInterruptedTasksMarksRunningTasksCancelled(t *testing.T) {
	s := &stubStore{
		tasks: map[string]*models.Task{
			"task-1": {
				ID:     "task-1",
				Status: models.TaskStatusRunning,
			},
			"task-2": {
				ID:     "task-2",
				Status: models.TaskStatusCompleted,
			},
		},
	}

	mgr := &Manager{store: s, running: make(map[string]context.CancelFunc)}

	count, err := mgr.RecoverInterruptedTasks(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	task1, err := s.GetTask(context.Background(), "task-1")
	require.NoError(t, err)
	assert.Equal(t, models.TaskStatusCancelled, task1.Status)
	assert.NotNil(t, task1.FinishedAt)
	assert.Contains(t, task1.ErrorMessage, "service shutdown or restart")

	task2, err := s.GetTask(context.Background(), "task-2")
	require.NoError(t, err)
	assert.Equal(t, models.TaskStatusCompleted, task2.Status)
}

func TestRecalculateAssetRisksUsesHighestVulnerabilitySeverity(t *testing.T) {
	s := &stubStore{
		tasks: map[string]*models.Task{},
	}

	assets := []models.Asset{
		{ID: "asset-1", TaskID: "task-1", IP: "1.1.1.1", Port: 18789, AuthMode: "token_auth", RiskLevel: models.RiskLow},
		{ID: "asset-2", TaskID: "task-1", IP: "1.1.1.2", Port: 18789, AuthMode: "token_auth", RiskLevel: models.RiskLow},
	}
	vulns := []models.Vulnerability{
		{AssetID: "asset-1", Severity: models.SeverityCritical},
		{AssetID: "asset-2", Severity: models.SeverityMedium},
	}

	s.listAssets = func(context.Context, store.AssetFilter) ([]models.Asset, int64, error) {
		return assets, int64(len(assets)), nil
	}
	s.listVulnerabilities = func(context.Context, store.VulnFilter) ([]models.Vulnerability, int64, error) {
		return vulns, int64(len(vulns)), nil
	}

	updatedAssets := map[string]models.Asset{}
	s.upsertAsset = func(_ context.Context, asset *models.Asset) error {
		updatedAssets[asset.ID] = *asset
		return nil
	}

	mgr := &Manager{store: s, running: make(map[string]context.CancelFunc)}

	updated, err := mgr.RecalculateAssetRisks(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, updated)
	assert.Equal(t, models.RiskCritical, updatedAssets["asset-1"].RiskLevel)
	assert.Equal(t, models.RiskMedium, updatedAssets["asset-2"].RiskLevel)
}
