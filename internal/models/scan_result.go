package models

import "time"

type ScanResult struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	TaskID    string    `json:"task_id" gorm:"size:36;not null;index"`
	IP        string    `json:"ip" gorm:"size:45;not null;index"`
	Port      int       `json:"port" gorm:"not null"`
	Phase     string    `json:"phase" gorm:"size:10;not null"` // "l1", "l2", "l3"
	ProbeType string    `json:"probe_type" gorm:"size:32"`
	Success   bool      `json:"success"`
	Matched   bool      `json:"matched"`
	Details   string    `json:"details,omitempty" gorm:"type:text"`
	Error     string    `json:"error,omitempty" gorm:"type:text"`
	Duration  int64     `json:"duration_ms"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (ScanResult) TableName() string { return "scan_results" }
