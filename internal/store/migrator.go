package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AutoScan/agentscan/internal/core/logger"
	"github.com/AutoScan/agentscan/internal/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// MigrationRecord tracks applied migrations in the database.
type MigrationRecord struct {
	ID        uint      `gorm:"primaryKey"`
	Version   string    `gorm:"size:32;uniqueIndex;not null"`
	Name      string    `gorm:"size:255;not null"`
	AppliedAt time.Time `gorm:"autoCreateTime"`
}

func (MigrationRecord) TableName() string { return "schema_migrations" }

// Migration defines a versioned schema change.
type Migration struct {
	Version string
	Name    string
	Up      func(tx *gorm.DB) error
}

// Migrate runs all pending migrations in order.
// This replaces raw AutoMigrate for production use, providing version tracking.
func Migrate(db *gorm.DB) error {
	log := logger.Named("migrator")

	if err := db.AutoMigrate(&MigrationRecord{}); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	for _, m := range migrations {
		var count int64
		db.Model(&MigrationRecord{}).Where("version = ?", m.Version).Count(&count)
		if count > 0 {
			continue
		}

		log.Info("applying migration", zap.String("version", m.Version), zap.String("name", m.Name))

		if err := db.Transaction(func(tx *gorm.DB) error {
			if err := m.Up(tx); err != nil {
				return err
			}
			return tx.Create(&MigrationRecord{
				Version: m.Version,
				Name:    m.Name,
			}).Error
		}); err != nil {
			return fmt.Errorf("migration %s (%s) failed: %w", m.Version, m.Name, err)
		}
	}

	log.Info("migrations complete", zap.Int("total", len(migrations)))
	return nil
}

// migrations is the ordered list of schema migrations.
// Add new migrations to the end only. Never reorder or modify existing ones.
var migrations = []Migration{
	{
		Version: "001",
		Name:    "initial_schema",
		Up: func(tx *gorm.DB) error {
			type Task struct {
				ID              string    `gorm:"primaryKey;size:36"`
				Name            string    `gorm:"size:255;not null"`
				Description     string    `gorm:"size:1024"`
				Status          string    `gorm:"size:20;not null;default:pending;index"`
				Type            string    `gorm:"size:20;not null;default:instant"`
				CronExpr        string    `gorm:"size:64"`
				Targets         string    `gorm:"type:text;not null"`
				Ports           string    `gorm:"size:512"`
				ScanDepth       string    `gorm:"size:10;not null;default:l3"`
				RateLimit       int       `gorm:"default:10000"`
				Concurrency     int       `gorm:"default:100"`
				Timeout         int       `gorm:"default:3"`
				EnableMDNS      bool      `gorm:"default:true"`
				TotalTargets    int       `gorm:"default:0"`
				ScannedTargets  int       `gorm:"default:0"`
				OpenPorts       int       `gorm:"default:0"`
				FoundAgents     int       `gorm:"default:0"`
				FoundVulns      int       `gorm:"default:0"`
				ProgressPercent float64   `gorm:"default:0"`
				ErrorMessage    string    `gorm:"type:text"`
				CreatedAt       time.Time `gorm:"autoCreateTime"`
				UpdatedAt       time.Time `gorm:"autoUpdateTime"`
				StartedAt       *time.Time
				FinishedAt      *time.Time
			}
			type Asset struct {
				ID           string  `gorm:"primaryKey;size:36"`
				TaskID       string  `gorm:"size:36;index"`
				IP           string  `gorm:"size:45;not null;index"`
				Port         int     `gorm:"not null"`
				AgentType    string  `gorm:"size:64;index"`
				Version      string  `gorm:"size:64"`
				AuthMode     string  `gorm:"size:32"`
				AgentID      string  `gorm:"size:128"`
				Confidence   float64 `gorm:"default:0"`
				RiskLevel    string  `gorm:"size:20;index"`
				Status       string  `gorm:"size:20;default:active"`
				Country      string  `gorm:"size:64"`
				Province     string  `gorm:"size:64"`
				City         string  `gorm:"size:64"`
				ISP          string  `gorm:"size:128"`
				ASN          int
				ProbeDetails string    `gorm:"type:text"`
				Metadata     string    `gorm:"type:text"`
				FirstSeenAt  time.Time `gorm:"autoCreateTime"`
				LastSeenAt   time.Time `gorm:"autoUpdateTime"`
			}
			type Vulnerability struct {
				ID          string    `gorm:"primaryKey;size:36"`
				AssetID     string    `gorm:"size:36;not null;index"`
				TaskID      string    `gorm:"size:36;index"`
				CVEID       string    `gorm:"size:32;index"`
				Title       string    `gorm:"size:512;not null"`
				Severity    string    `gorm:"size:20;not null;index"`
				CVSS        float64   `gorm:"default:0"`
				Description string    `gorm:"type:text"`
				Remediation string    `gorm:"type:text"`
				Evidence    string    `gorm:"type:text"`
				CheckType   string    `gorm:"size:32"`
				DetectedAt  time.Time `gorm:"autoCreateTime"`
			}
			type ScanResult struct {
				ID     string `gorm:"primaryKey;size:36"`
				TaskID string `gorm:"size:36;index"`
				IP     string `gorm:"size:45"`
				Port   int
				Open   bool
				Phase  string    `gorm:"size:10"`
				Data   string    `gorm:"type:text"`
				At     time.Time `gorm:"autoCreateTime"`
			}
			type User struct {
				ID        string    `gorm:"primaryKey;size:36"`
				Username  string    `gorm:"size:64;uniqueIndex;not null"`
				Password  string    `gorm:"size:128;not null"`
				Role      string    `gorm:"size:20;default:admin"`
				CreatedAt time.Time `gorm:"autoCreateTime"`
				UpdatedAt time.Time `gorm:"autoUpdateTime"`
			}
			return tx.AutoMigrate(&Task{}, &Asset{}, &Vulnerability{}, &ScanResult{}, &User{})
		},
	},
	{
		Version: "002",
		Name:    "add_alert_tables",
		Up: func(tx *gorm.DB) error {
			type AlertRule struct {
				ID        string    `gorm:"primaryKey;size:36"`
				Name      string    `gorm:"size:128;not null"`
				Event     string    `gorm:"size:64;not null"`
				Condition string    `gorm:"size:64;not null"`
				Threshold string    `gorm:"size:64"`
				Enabled   bool      `gorm:"default:true"`
				CreatedAt time.Time `gorm:"autoCreateTime"`
				UpdatedAt time.Time `gorm:"autoUpdateTime"`
			}
			type AlertRecord struct {
				ID        string    `gorm:"primaryKey;size:36"`
				EventType string    `gorm:"size:64;not null;index"`
				RuleName  string    `gorm:"size:128"`
				Data      string    `gorm:"type:text"`
				Sent      bool      `gorm:"default:false"`
				Error     string    `gorm:"size:512"`
				CreatedAt time.Time `gorm:"autoCreateTime"`
			}
			return tx.AutoMigrate(&AlertRule{}, &AlertRecord{})
		},
	},
	{
		Version: "003",
		Name:    "add_task_events",
		Up: func(tx *gorm.DB) error {
			type TaskEvent struct {
				ID        string    `gorm:"primaryKey;size:36"`
				TaskID    string    `gorm:"size:36;not null;index"`
				EventType string    `gorm:"size:64;not null;index"`
				Summary   string    `gorm:"type:text"`
				Payload   string    `gorm:"type:text"`
				EventTime time.Time `gorm:"index"`
				CreatedAt time.Time `gorm:"autoCreateTime"`
			}
			return tx.AutoMigrate(&TaskEvent{})
		},
	},
	{
		Version: "004",
		Name:    "add_vulnerability_external_ids",
		Up: func(tx *gorm.DB) error {
			type Vulnerability struct {
				CNNVDID string `gorm:"size:32;index"`
				GHSAID  string `gorm:"size:32;index"`
			}
			return tx.Table("vulnerabilities").AutoMigrate(&Vulnerability{})
		},
	},
	{
		Version: "005",
		Name:    "refresh_scan_results_schema",
		Up: func(tx *gorm.DB) error {
			type ScanResult struct {
				ProbeType string `gorm:"size:32"`
				Success   bool
				Matched   bool
				Details   string `gorm:"type:text"`
				Error     string `gorm:"type:text"`
				Duration  int64
				CreatedAt time.Time `gorm:"autoCreateTime"`
			}
			return tx.Table("scan_results").AutoMigrate(&ScanResult{})
		},
	},
	{
		Version: "006",
		Name:    "add_vulnerability_description_zh",
		Up: func(tx *gorm.DB) error {
			type Vulnerability struct {
				DescriptionZH string `gorm:"type:text"`
			}
			return tx.Table("vulnerabilities").AutoMigrate(&Vulnerability{})
		},
	},
	{
		Version: "007",
		Name:    "repair_missing_assets_from_task_events",
		Up: func(tx *gorm.DB) error {
			type taskEventRow struct {
				Payload   string
				EventTime time.Time
			}

			var rows []taskEventRow
			if err := tx.Table("task_events").
				Select("payload, event_time").
				Where("event_type = ?", "agent.identified").
				Find(&rows).Error; err != nil {
				return err
			}

			for _, row := range rows {
				if strings.TrimSpace(row.Payload) == "" {
					continue
				}

				var asset models.Asset
				if err := json.Unmarshal([]byte(row.Payload), &asset); err != nil {
					continue
				}
				if asset.ID == "" || strings.TrimSpace(asset.IP) == "" || asset.Port == 0 {
					continue
				}

				var count int64
				if err := tx.Table("assets").Where("id = ?", asset.ID).Count(&count).Error; err != nil {
					return err
				}
				if count > 0 {
					continue
				}

				if asset.Status == "" {
					asset.Status = models.AssetStatusActive
				}
				if asset.RiskLevel == "" {
					asset.RiskLevel = models.RiskFromAuthMode(asset.AuthMode)
				}
				if asset.FirstSeenAt.IsZero() {
					asset.FirstSeenAt = row.EventTime
				}
				if asset.LastSeenAt.IsZero() {
					asset.LastSeenAt = row.EventTime
				}

				if err := tx.Table("assets").Create(&asset).Error; err != nil {
					return err
				}
			}

			return nil
		},
	},
	{
		Version: "008",
		Name:    "remove_legacy_ghsa_only_findings",
		Up: func(tx *gorm.DB) error {
			type staleVulnRow struct {
				ID      string
				AssetID string
				TaskID  string
			}
			type assetRiskRow struct {
				ID       string
				AuthMode string
			}
			type vulnSeverityRow struct {
				Severity string
			}
			var stale []staleVulnRow
			if err := tx.Table("vulnerabilities").
				Select("id, asset_id, task_id").
				Where("check_type = ?", "cve_match").
				Where("COALESCE(TRIM(cve_id), '') = ''").
				Where("COALESCE(TRIM(cnnvd_id), '') = ''").
				Where("COALESCE(TRIM(ghsa_id), '') <> ''").
				Find(&stale).Error; err != nil {
				return err
			}
			if len(stale) == 0 {
				return nil
			}

			ids := make([]string, 0, len(stale))
			affectedAssetIDs := make(map[string]struct{}, len(stale))
			affectedTaskIDs := make(map[string]struct{}, len(stale))
			for _, row := range stale {
				ids = append(ids, row.ID)
				if row.AssetID != "" {
					affectedAssetIDs[row.AssetID] = struct{}{}
				}
				if row.TaskID != "" {
					affectedTaskIDs[row.TaskID] = struct{}{}
				}
			}

			if err := tx.Where("id IN ?", ids).Delete(&models.Vulnerability{}).Error; err != nil {
				return err
			}

			for assetID := range affectedAssetIDs {
				var asset assetRiskRow
				if err := tx.Table("assets").Select("id, auth_mode").Where("id = ?", assetID).First(&asset).Error; err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						continue
					}
					return err
				}

				var rows []vulnSeverityRow
				if err := tx.Table("vulnerabilities").Select("severity").Where("asset_id = ?", assetID).Find(&rows).Error; err != nil {
					return err
				}

				severities := make([]models.Severity, 0, len(rows))
				for _, row := range rows {
					if strings.TrimSpace(row.Severity) == "" {
						continue
					}
					severities = append(severities, models.Severity(row.Severity))
				}

				derived := models.DeriveAssetRisk(asset.AuthMode, severities)
				if err := tx.Table("assets").Where("id = ?", assetID).Update("risk_level", derived).Error; err != nil {
					return err
				}
			}

			for taskID := range affectedTaskIDs {
				var count int64
				if err := tx.Table("vulnerabilities").Where("task_id = ?", taskID).Count(&count).Error; err != nil {
					return err
				}
				if err := tx.Table("tasks").Where("id = ?", taskID).Update("found_vulns", count).Error; err != nil {
					return err
				}

				var foundAgents int64
				if err := tx.Table("assets").Where("task_id = ?", taskID).Count(&foundAgents).Error; err != nil {
					return err
				}
				if err := tx.Table("tasks").Where("id = ?", taskID).Update("found_agents", foundAgents).Error; err != nil {
					return err
				}
			}

			return nil
		},
	},
}
