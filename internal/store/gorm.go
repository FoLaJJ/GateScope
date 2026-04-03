package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AutoScan/agentscan/internal/core/config"
	"github.com/AutoScan/agentscan/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type gormStore struct {
	db       *gorm.DB
	isSQLite bool
	writeMu  sync.Mutex
}

// NewGormStore creates a Store backed by GORM using the full application config.
func NewGormStore(cfg *config.Config) (Store, error) {
	var dialector gorm.Dialector
	switch cfg.Database.Driver {
	case "sqlite":
		dialector = sqlite.Open(cfg.Database.DSN)
	case "postgres":
		dialector = openPostgres(cfg.Database.DSN)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", cfg.Database.Driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}
	isSQLite := cfg.Database.Driver == "sqlite"
	if isSQLite {
		// SQLite is prone to "database is locked" when multiple pooled connections
		// try to write concurrently. Keep a single shared connection and enable
		// a busy timeout for transient writer contention.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		if err := db.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
			return nil, fmt.Errorf("set sqlite busy_timeout: %w", err)
		}
		if !isInMemorySQLite(cfg.Database.DSN) {
			if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
				return nil, fmt.Errorf("set sqlite journal_mode wal: %w", err)
			}
		}
	} else {
		if cfg.Database.MaxOpenConn > 0 {
			sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConn)
		}
		if cfg.Database.MaxIdleConn > 0 {
			sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConn)
		}
		if cfg.Database.MaxLifetime > 0 {
			sqlDB.SetConnMaxLifetime(cfg.Database.MaxLifetime)
		}
	}
	if cfg.Database.MaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.Database.MaxLifetime)
	}

	return &gormStore{db: db, isSQLite: isSQLite}, nil
}

// NewGormStoreSimple creates a Store with minimal config (for tests).
func NewGormStoreSimple(driver, dsn string) (Store, error) {
	return NewGormStore(&config.Config{
		Database: config.DatabaseConfig{Driver: driver, DSN: dsn},
	})
}

func openPostgres(dsn string) gorm.Dialector {
	return postgres.Open(dsn)
}

func (s *gormStore) AutoMigrate() error {
	return Migrate(s.db)
}

func (s *gormStore) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

// ---------- Tasks ----------

func (s *gormStore) CreateTask(ctx context.Context, task *models.Task) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		enableMDNS := task.EnableMDNS
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(task).Error; err != nil {
				return err
			}
			if !enableMDNS {
				return tx.Model(task).Update("enable_m_dns", false).Error
			}
			return nil
		})
	})
}

func (s *gormStore) GetTask(ctx context.Context, id string) (*models.Task, error) {
	var task models.Task
	if err := s.db.WithContext(ctx).First(&task, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *gormStore) UpdateTask(ctx context.Context, task *models.Task) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Save(task).Error
	})
}

func (s *gormStore) DeleteTask(ctx context.Context, id string) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Delete(&models.TaskEvent{}, "task_id = ?", id).Error; err != nil {
				return err
			}
			if err := tx.Delete(&models.Vulnerability{}, "task_id = ?", id).Error; err != nil {
				return err
			}
			if err := tx.Delete(&models.Asset{}, "task_id = ?", id).Error; err != nil {
				return err
			}
			if err := tx.Delete(&models.ScanResult{}, "task_id = ?", id).Error; err != nil {
				return err
			}
			return tx.Delete(&models.Task{}, "id = ?", id).Error
		})
	})
}

func (s *gormStore) ListTasks(ctx context.Context, filter TaskFilter) ([]models.Task, int64, error) {
	q := s.db.WithContext(ctx).Model(&models.Task{})
	if filter.Status != nil {
		q = q.Where("status = ?", *filter.Status)
	}
	if filter.Type != nil {
		q = q.Where("type = ?", *filter.Type)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	q = q.Limit(limit)
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}

	var tasks []models.Task
	err := q.Order("created_at DESC").Find(&tasks).Error
	return tasks, total, err
}

func (s *gormStore) CreateTaskEvent(ctx context.Context, event *models.TaskEvent) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(event).Error
	})
}

func (s *gormStore) ListTaskEvents(ctx context.Context, taskID string, limit int) ([]models.TaskEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	var events []models.TaskEvent
	err := s.db.WithContext(ctx).
		Where("task_id = ?", taskID).
		Order("event_time DESC, created_at DESC").
		Limit(limit).
		Find(&events).Error
	return events, err
}

// ---------- Assets ----------

func (s *gormStore) CreateAsset(ctx context.Context, asset *models.Asset) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(asset).Error
	})
}

func (s *gormStore) GetAsset(ctx context.Context, id string) (*models.Asset, error) {
	var asset models.Asset
	if err := s.db.WithContext(ctx).First(&asset, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &asset, nil
}

func (s *gormStore) UpsertAsset(ctx context.Context, asset *models.Asset) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			var existing models.Asset
			err := tx.Where("ip = ? AND port = ? AND task_id = ?", asset.IP, asset.Port, asset.TaskID).First(&existing).Error
			switch {
			case err == nil:
				existing.AgentType = asset.AgentType
				existing.Version = asset.Version
				existing.AuthMode = asset.AuthMode
				existing.AgentID = asset.AgentID
				existing.Confidence = asset.Confidence
				existing.RiskLevel = asset.RiskLevel
				existing.Status = models.AssetStatusActive
				existing.ProbeDetails = asset.ProbeDetails
				existing.Metadata = asset.Metadata
				if err := tx.Save(&existing).Error; err != nil {
					return err
				}
				asset.ID = existing.ID
				return nil
			case errors.Is(err, gorm.ErrRecordNotFound):
				return tx.Create(asset).Error
			default:
				return err
			}
		})
	})
}

func (s *gormStore) ListAssets(ctx context.Context, filter AssetFilter) ([]models.Asset, int64, error) {
	q := s.db.WithContext(ctx).Model(&models.Asset{})
	if filter.TaskID != "" {
		q = q.Where("task_id = ?", filter.TaskID)
	}
	if filter.AgentType != "" {
		q = q.Where("agent_type = ?", filter.AgentType)
	}
	if filter.RiskLevel != nil {
		q = q.Where("risk_level = ?", *filter.RiskLevel)
	}
	if filter.IP != "" {
		q = q.Where("ip LIKE ?", "%"+filter.IP+"%")
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	q = q.Limit(limit)
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}

	var assets []models.Asset
	err := q.Order("last_seen_at DESC").Find(&assets).Error
	return assets, total, err
}

// ---------- Vulnerabilities ----------

func (s *gormStore) CreateVulnerability(ctx context.Context, vuln *models.Vulnerability) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(vuln).Error
	})
}

func (s *gormStore) GetVulnerability(ctx context.Context, id string) (*models.Vulnerability, error) {
	var v models.Vulnerability
	if err := s.db.WithContext(ctx).First(&v, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *gormStore) ListVulnerabilities(ctx context.Context, filter VulnFilter) ([]models.Vulnerability, int64, error) {
	q := s.db.WithContext(ctx).Model(&models.Vulnerability{})
	if filter.TaskID != "" {
		q = q.Where("task_id = ?", filter.TaskID)
	}
	if filter.AssetID != "" {
		q = q.Where("asset_id = ?", filter.AssetID)
	}
	if filter.Severity != nil {
		q = q.Where("severity = ?", *filter.Severity)
	}
	if filter.Identifier != "" {
		switch filter.IdentifierType {
		case "cve":
			q = q.Where("cve_id = ?", filter.Identifier)
		case "cnnvd":
			q = q.Where("cnnvd_id = ?", filter.Identifier)
		case "ghsa":
			q = q.Where("ghsa_id = ?", filter.Identifier)
		default:
			q = q.Where("cve_id = ? OR cnnvd_id = ? OR ghsa_id = ?", filter.Identifier, filter.Identifier, filter.Identifier)
		}
	}
	if filter.CheckType != "" {
		q = q.Where("check_type = ?", filter.CheckType)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	q = q.Limit(limit)
	if filter.Offset > 0 {
		q = q.Offset(filter.Offset)
	}

	var vulns []models.Vulnerability
	err := q.Order("detected_at DESC").Find(&vulns).Error
	return vulns, total, err
}

func (s *gormStore) ListVulnsByAsset(ctx context.Context, assetID string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := s.db.WithContext(ctx).Where("asset_id = ?", assetID).Find(&vulns).Error
	return vulns, err
}

// ---------- Scan Results ----------

func (s *gormStore) CreateScanResult(ctx context.Context, result *models.ScanResult) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(result).Error
	})
}

func (s *gormStore) ListScanResults(ctx context.Context, taskID string) ([]models.ScanResult, error) {
	var results []models.ScanResult
	err := s.db.WithContext(ctx).Where("task_id = ?", taskID).Find(&results).Error
	return results, err
}

// ---------- Users ----------

func (s *gormStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *gormStore) CreateUser(ctx context.Context, user *models.User) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(user).Error
	})
}

// ---------- Alert Rules ----------

func (s *gormStore) ListAlertRules(ctx context.Context) ([]models.AlertRule, error) {
	var rules []models.AlertRule
	err := s.db.WithContext(ctx).Order("created_at ASC").Find(&rules).Error
	return rules, err
}

func (s *gormStore) SaveAlertRules(ctx context.Context, rules []models.AlertRule) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Where("1 = 1").Delete(&models.AlertRule{}).Error; err != nil {
				return err
			}
			if len(rules) == 0 {
				return nil
			}
			return tx.Create(&rules).Error
		})
	})
}

// ---------- Alert Records ----------

func (s *gormStore) CreateAlertRecord(ctx context.Context, record *models.AlertRecord) error {
	return s.withWriteSession(ctx, func(db *gorm.DB) error {
		return db.Create(record).Error
	})
}

func (s *gormStore) ListAlertRecords(ctx context.Context, limit int) ([]models.AlertRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	var records []models.AlertRecord
	err := s.db.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&records).Error
	return records, err
}

func (s *gormStore) withWriteSession(ctx context.Context, fn func(db *gorm.DB) error) error {
	if s.isSQLite {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}

	db := s.db.WithContext(ctx)
	attempts := 1
	if s.isSQLite {
		attempts = 5
	}

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		err = fn(db)
		if !isSQLiteBusyError(err) || attempt == attempts {
			return err
		}
		time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
	}
	return err
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked") || strings.Contains(msg, "database is busy")
}

func isInMemorySQLite(dsn string) bool {
	normalized := strings.ToLower(strings.TrimSpace(dsn))
	return normalized == ":memory:" || strings.Contains(normalized, "mode=memory")
}

// ---------- Dashboard ----------

func (s *gormStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{
		RiskDist:      make(map[models.RiskLevel]int64),
		SeverityDist:  make(map[models.Severity]int64),
		AgentTypeDist: make(map[string]int64),
	}

	if err := s.db.WithContext(ctx).Model(&models.Task{}).Count(&stats.TotalTasks).Error; err != nil {
		return nil, fmt.Errorf("count tasks: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&models.Asset{}).Count(&stats.TotalAssets).Error; err != nil {
		return nil, fmt.Errorf("count assets: %w", err)
	}
	if err := s.db.WithContext(ctx).Model(&models.Vulnerability{}).Count(&stats.TotalVulns).Error; err != nil {
		return nil, fmt.Errorf("count vulns: %w", err)
	}

	type kv struct {
		K string
		V int64
	}

	var riskRows []kv
	s.db.WithContext(ctx).Model(&models.Asset{}).
		Select("risk_level as k, count(*) as v").Group("risk_level").Scan(&riskRows)
	for _, r := range riskRows {
		stats.RiskDist[models.RiskLevel(r.K)] = r.V
	}

	var sevRows []kv
	s.db.WithContext(ctx).Model(&models.Vulnerability{}).
		Select("severity as k, count(*) as v").Group("severity").Scan(&sevRows)
	for _, r := range sevRows {
		stats.SeverityDist[models.Severity(r.K)] = r.V
	}

	var typeRows []kv
	s.db.WithContext(ctx).Model(&models.Asset{}).
		Select("agent_type as k, count(*) as v").Group("agent_type").Scan(&typeRows)
	for _, r := range typeRows {
		stats.AgentTypeDist[r.K] = r.V
	}

	return stats, nil
}
