package models

import "time"

type User struct {
	ID        string    `json:"id" gorm:"primaryKey;size:36"`
	Username  string    `json:"username" gorm:"size:64;uniqueIndex;not null"`
	Password  string    `json:"-" gorm:"size:128;not null"`
	Role      string    `json:"role" gorm:"size:20;default:admin"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (User) TableName() string { return "users" }
