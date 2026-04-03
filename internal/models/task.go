package models

import "time"

type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusPaused    TaskStatus = "paused"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

type TaskType string

const (
	TaskTypeInstant   TaskType = "instant"
	TaskTypeScheduled TaskType = "scheduled"
)

type ScanDepth string

const (
	ScanDepthL1  ScanDepth = "l1"
	ScanDepthL2  ScanDepth = "l2"
	ScanDepthL3  ScanDepth = "l3"
)

type Task struct {
	ID          string     `json:"id" gorm:"primaryKey;size:36"`
	Name        string     `json:"name" gorm:"size:255;not null"`
	Description string     `json:"description" gorm:"size:1024"`
	Status      TaskStatus `json:"status" gorm:"size:20;not null;default:pending;index"`
	Type        TaskType   `json:"type" gorm:"size:20;not null;default:instant"`
	CronExpr    string     `json:"cron_expr,omitempty" gorm:"size:64"`

	Targets     string    `json:"targets" gorm:"type:text;not null"`
	Ports       string    `json:"ports" gorm:"size:512"`
	ScanDepth   ScanDepth `json:"scan_depth" gorm:"size:10;not null;default:l3"`
	RateLimit   int       `json:"rate_limit" gorm:"default:10000"`
	Concurrency int       `json:"concurrency" gorm:"default:100"`
	Timeout     int       `json:"timeout" gorm:"default:3"`
	EnableMDNS  bool      `json:"enable_mdns" gorm:"default:true"`

	TotalTargets    int     `json:"total_targets" gorm:"default:0"`
	ScannedTargets  int     `json:"scanned_targets" gorm:"default:0"`
	OpenPorts       int     `json:"open_ports" gorm:"default:0"`
	FoundAgents     int     `json:"found_agents" gorm:"default:0"`
	FoundVulns      int     `json:"found_vulns" gorm:"default:0"`
	ProgressPercent float64 `json:"progress_percent" gorm:"default:0"`
	ErrorMessage    string  `json:"error_message,omitempty" gorm:"type:text"`

	CreatedAt  time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt  time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (Task) TableName() string { return "tasks" }
