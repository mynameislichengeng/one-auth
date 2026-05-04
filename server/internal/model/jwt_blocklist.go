package model

import "time"

// JWTBlocklist access_token 黑名单（用户登出/强制下线时加进来）。
// D-F1：必须走 MySQL，不能走 cache（重启后丢失会让已撤销 token 复活）。
type JWTBlocklist struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	JTI       string    `gorm:"column:jti;type:char(26);uniqueIndex:uk_jti"`
	UserID    uint64    `gorm:"column:user_id;index:idx_user"`
	Reason    string    `gorm:"column:reason;type:varchar(64)"`
	RevokedAt time.Time `gorm:"column:revoked_at"`
	ExpiresAt time.Time `gorm:"column:expires_at;index:idx_expires"`
}

func (JWTBlocklist) TableName() string { return "jwt_blocklist" }

const (
	BlocklistReasonLogout         = "logout"
	BlocklistReasonPasswordChange = "password_change"
	BlocklistReasonAdminRevoke    = "admin_revoke"
	BlocklistReasonSessionRevoke  = "session_revoke"
	BlocklistReasonRefreshReplay  = "refresh_replay"
)
