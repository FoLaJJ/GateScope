package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

type AssetStatus string

const (
	AssetStatusActive   AssetStatus = "active"
	AssetStatusInactive AssetStatus = "inactive"
	AssetStatusUnknown  AssetStatus = "unknown"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskInfo     RiskLevel = "info"
)

type Asset struct {
	ID         string      `json:"id" gorm:"primaryKey;size:36"`
	TaskID     string      `json:"task_id" gorm:"size:36;index"`
	IP         string      `json:"ip" gorm:"size:45;not null;index"`
	Port       int         `json:"port" gorm:"not null"`
	AgentType  string      `json:"agent_type" gorm:"size:64;index"`
	Version    string      `json:"version" gorm:"size:64"`
	AuthMode   string      `json:"auth_mode" gorm:"size:32"`
	AgentID    string      `json:"agent_id" gorm:"size:128"`
	Confidence float64     `json:"confidence" gorm:"default:0"`
	RiskLevel  RiskLevel   `json:"risk_level" gorm:"size:20;index"`
	Status     AssetStatus `json:"status" gorm:"size:20;default:active"`

	Country  string `json:"country,omitempty" gorm:"size:64"`
	Province string `json:"province,omitempty" gorm:"size:64"`
	City     string `json:"city,omitempty" gorm:"size:64"`
	ISP      string `json:"isp,omitempty" gorm:"size:128"`
	ASN      int    `json:"asn,omitempty"`

	ProbeDetails JSONMap `json:"probe_details,omitempty" gorm:"type:text"`
	Metadata     JSONMap `json:"metadata,omitempty" gorm:"type:text"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"autoCreateTime"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"autoUpdateTime"`
}

func (Asset) TableName() string { return "assets" }

// JSONMap is a map[string]any that serializes to JSON for both SQLite and PostgreSQL.
type JSONMap map[string]any

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	b, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("json marshal: %w", err)
	}
	return string(b), nil
}

func (j *JSONMap) Scan(value any) error {
	if value == nil {
		*j = nil
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case string:
		if v == "" {
			*j = nil
			return nil
		}
		bytes = []byte(v)
	case []byte:
		if len(v) == 0 {
			*j = nil
			return nil
		}
		bytes = v
	default:
		return fmt.Errorf("unsupported type for JSONMap: %T", value)
	}
	return json.Unmarshal(bytes, j)
}

func RiskFromAuthMode(authMode string) RiskLevel {
	switch authMode {
	case "none", "open", "":
		return RiskCritical
	case "origin_restricted":
		return RiskMedium
	case "token_auth", "device_auth":
		return RiskLow
	default:
		return RiskMedium
	}
}
