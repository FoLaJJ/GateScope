package models

import "time"

type AlertRule struct {
	ID        string `json:"id" gorm:"primaryKey;size:36"`
	Name      string `json:"name" gorm:"size:128;not null"`
	Event     string `json:"event" gorm:"size:64;not null"`
	Condition string `json:"condition" gorm:"size:64;not null"`
	Threshold string `json:"threshold" gorm:"size:64"`
	Enabled   bool   `json:"enabled" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (AlertRule) TableName() string { return "alert_rules" }

type AlertRecord struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	EventType string    `json:"event_type" gorm:"size:64;not null;index"`
	RuleName  string    `json:"rule_name" gorm:"size:128"`
	Data      JSONMap   `json:"data" gorm:"type:text"`
	Sent      bool      `json:"sent" gorm:"default:false"`
	Error     string    `json:"error,omitempty" gorm:"size:512"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (AlertRecord) TableName() string { return "alert_records" }
