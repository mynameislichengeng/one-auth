package model

import "time"

// AuthSession 是 oneauth 自身的 SSO cookie session（详见 02 文档 §IV.1）。
// 浏览器持有的 oneauth_sid cookie 对应这一行的 SessionID。
// 这是 SSO 灵魂——让用户在 oneauth 域下登录一次，访问其他 client 时静默授权。
type AuthSession struct {
	ID         uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	SessionID  string     `gorm:"column:session_id;type:char(64);uniqueIndex:uk_session_id"`
	UserID     uint64     `gorm:"column:user_id;index:idx_user,priority:1"`
	IP         string     `gorm:"column:ip;type:varchar(45)"`
	UserAgent  string     `gorm:"column:user_agent;type:text"`
	CreatedAt  time.Time  `gorm:"column:created_at"`
	LastSeenAt time.Time  `gorm:"column:last_seen_at"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;index:idx_expires"`
	RevokedAt  *time.Time `gorm:"column:revoked_at;index:idx_user,priority:2"`
}

func (AuthSession) TableName() string { return "auth_sessions" }
