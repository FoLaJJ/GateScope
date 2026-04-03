package models

import "time"

type TaskEvent struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	TaskID    string    `json:"task_id" gorm:"size:36;not null;index"`
	EventType string    `json:"event_type" gorm:"size:64;not null;index"`
	Summary   string    `json:"summary" gorm:"type:text"`
	Payload   JSONMap   `json:"payload,omitempty" gorm:"type:text"`
	EventTime time.Time `json:"event_time" gorm:"index"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

func (TaskEvent) TableName() string { return "task_events" }
