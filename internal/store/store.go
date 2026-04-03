package store

import (
	"context"

	"github.com/AutoScan/agentscan/internal/models"
)

type TaskFilter struct {
	Status *models.TaskStatus
	Type   *models.TaskType
	Limit  int
	Offset int
}

type AssetFilter struct {
	TaskID    string
	AgentType string
	RiskLevel *models.RiskLevel
	IP        string
	Limit     int
	Offset    int
}

type VulnFilter struct {
	TaskID    string
	AssetID   string
	Severity  *models.Severity
	CVEID     string
	CheckType string
	Limit     int
	Offset    int
}

type DashboardStats struct {
	TotalTasks    int64                      `json:"total_tasks"`
	TotalAssets   int64                      `json:"total_assets"`
	TotalVulns    int64                      `json:"total_vulns"`
	RiskDist      map[models.RiskLevel]int64 `json:"risk_distribution"`
	SeverityDist  map[models.Severity]int64  `json:"severity_distribution"`
	AgentTypeDist map[string]int64           `json:"agent_type_distribution"`
}

type Store interface {
	// Tasks
	CreateTask(ctx context.Context, task *models.Task) error
	GetTask(ctx context.Context, id string) (*models.Task, error)
	UpdateTask(ctx context.Context, task *models.Task) error
	DeleteTask(ctx context.Context, id string) error
	ListTasks(ctx context.Context, filter TaskFilter) ([]models.Task, int64, error)
	CreateTaskEvent(ctx context.Context, event *models.TaskEvent) error
	ListTaskEvents(ctx context.Context, taskID string, limit int) ([]models.TaskEvent, error)

	// Assets
	CreateAsset(ctx context.Context, asset *models.Asset) error
	GetAsset(ctx context.Context, id string) (*models.Asset, error)
	UpsertAsset(ctx context.Context, asset *models.Asset) error
	ListAssets(ctx context.Context, filter AssetFilter) ([]models.Asset, int64, error)

	// Vulnerabilities
	CreateVulnerability(ctx context.Context, vuln *models.Vulnerability) error
	GetVulnerability(ctx context.Context, id string) (*models.Vulnerability, error)
	ListVulnerabilities(ctx context.Context, filter VulnFilter) ([]models.Vulnerability, int64, error)
	ListVulnsByAsset(ctx context.Context, assetID string) ([]models.Vulnerability, error)

	// Scan Results
	CreateScanResult(ctx context.Context, result *models.ScanResult) error
	ListScanResults(ctx context.Context, taskID string) ([]models.ScanResult, error)

	// Users
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	CreateUser(ctx context.Context, user *models.User) error

	// Dashboard
	GetDashboardStats(ctx context.Context) (*DashboardStats, error)

	// Alert Rules
	ListAlertRules(ctx context.Context) ([]models.AlertRule, error)
	SaveAlertRules(ctx context.Context, rules []models.AlertRule) error

	// Alert History
	CreateAlertRecord(ctx context.Context, record *models.AlertRecord) error
	ListAlertRecords(ctx context.Context, limit int) ([]models.AlertRecord, error)

	// Lifecycle
	AutoMigrate() error
	Close() error
}
