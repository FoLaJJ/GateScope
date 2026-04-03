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
}

func (s *stubStore) CreateTask(context.Context, *models.Task) error        { return nil }
func (s *stubStore) GetTask(context.Context, string) (*models.Task, error) { return nil, nil }
func (s *stubStore) UpdateTask(context.Context, *models.Task) error        { return nil }
func (s *stubStore) DeleteTask(context.Context, string) error              { return nil }
func (s *stubStore) ListTasks(context.Context, store.TaskFilter) ([]models.Task, int64, error) {
	return nil, 0, nil
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
func (s *stubStore) ListAssets(context.Context, store.AssetFilter) ([]models.Asset, int64, error) {
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
func (s *stubStore) ListVulnerabilities(context.Context, store.VulnFilter) ([]models.Vulnerability, int64, error) {
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
func (s *stubStore) ListAlertRules(context.Context) ([]models.AlertRule, error)   { return nil, nil }
func (s *stubStore) SaveAlertRules(context.Context, []models.AlertRule) error     { return nil }
func (s *stubStore) CreateAlertRecord(context.Context, *models.AlertRecord) error { return nil }
func (s *stubStore) ListAlertRecords(context.Context, int) ([]models.AlertRecord, error) {
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
