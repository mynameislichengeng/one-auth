package model

import "time"

// User 用户身份。与 tenant 解耦（D-B5 成员关系型）。
type User struct {
	ID            uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	PublicID      string    `gorm:"column:public_id;type:char(26);uniqueIndex:uk_public_id"`
	Nickname      string    `gorm:"column:nickname;type:varchar(100)"`
	AvatarURL     string    `gorm:"column:avatar_url;type:varchar(500)"`
	Status        string    `gorm:"column:status;type:varchar(20);default:active"`
	StatusReason  string    `gorm:"column:status_reason;type:varchar(500)"`
	Metadata      []byte    `gorm:"column:metadata;type:json"`
	CreatedAt     time.Time `gorm:"column:created_at"`
	UpdatedAt     time.Time `gorm:"column:updated_at"`
	CreatedBy     *uint64   `gorm:"column:created_by"`
	UpdatedBy     *uint64   `gorm:"column:updated_by"`
	Deleted       bool      `gorm:"column:deleted;default:false"`
}

func (User) TableName() string { return "users" }

// UserStatus 常量。
const (
	UserStatusPending       = "pending"
	UserStatusActive        = "active"
	UserStatusSuspended     = "suspended"
	UserStatusBanned        = "banned"
	UserStatusPendingDelete = "pending_delete"
)
