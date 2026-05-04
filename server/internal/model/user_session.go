package model

import "time"

// UserSession 一个 OAuth client 下的 refresh token 会话（含 rotation 链）。
type UserSession struct {
	ID                uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID            uint64     `gorm:"column:user_id;index:idx_user_active,priority:1"`
	TenantID          uint64     `gorm:"column:tenant_id"`
	ClientID          string     `gorm:"column:client_id;type:varchar(64)"`
	RefreshTokenHash  string     `gorm:"column:refresh_token_hash;type:char(64);uniqueIndex:uk_refresh_hash"`
	FamilyID          string     `gorm:"column:family_id;type:char(26);index:idx_family"`
	ParentID          *uint64    `gorm:"column:parent_id"`
	DeviceType        string     `gorm:"column:device_type;type:varchar(32)"`
	DeviceID          string     `gorm:"column:device_id;type:varchar(128)"`
	UserAgent         string     `gorm:"column:user_agent;type:text"`
	IP                string     `gorm:"column:ip;type:varchar(45)"`
	IssuedAt          time.Time  `gorm:"column:issued_at"`
	RotatedAt         *time.Time `gorm:"column:rotated_at;index:idx_user_active,priority:2"`
	RevokedAt         *time.Time `gorm:"column:revoked_at;index:idx_user_active,priority:3"`
	ExpiresAt         time.Time  `gorm:"column:expires_at;index:idx_expires"`
	LastUsedAt        *time.Time `gorm:"column:last_used_at"`
}

func (UserSession) TableName() string { return "user_sessions" }
