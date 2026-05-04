package model

import "time"

// LoginAttempt 登录尝试日志（成功 + 失败都记，用于防爆破和审计）。
type LoginAttempt struct {
	ID            uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	AuthType      string    `gorm:"column:auth_type;type:varchar(32);index:idx_identifier_time,priority:1"`
	Identifier    string    `gorm:"column:identifier;type:varchar(255);index:idx_identifier_time,priority:2"`
	IP            string    `gorm:"column:ip;type:varchar(45);index:idx_ip_time,priority:1"`
	Success       bool      `gorm:"column:success"`
	FailureReason string    `gorm:"column:failure_reason;type:varchar(64)"`
	UserAgent     string    `gorm:"column:user_agent;type:text"`
	UserID        *uint64   `gorm:"column:user_id;index:idx_user_time,priority:1"`
	AttemptedAt   time.Time `gorm:"column:attempted_at;index:idx_identifier_time,priority:3;index:idx_ip_time,priority:2;index:idx_user_time,priority:2;index:idx_attempted_at"`
}

func (LoginAttempt) TableName() string { return "login_attempts" }

const (
	LoginFailureInvalidPassword = "invalid_password"
	LoginFailureUserNotFound    = "user_not_found"
	LoginFailureUserSuspended   = "user_suspended"
	LoginFailureLocked          = "too_many_attempts"
)
