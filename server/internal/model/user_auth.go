package model

import "time"

// UserAuth 登录凭证。(auth_type, auth_source, identifier) 全局唯一。
type UserAuth struct {
	ID          uint64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID      uint64     `gorm:"column:user_id;index"`
	AuthType    string     `gorm:"column:auth_type;type:varchar(32);uniqueIndex:uk_auth_identifier,priority:1"`
	AuthSource  string     `gorm:"column:auth_source;type:varchar(64);uniqueIndex:uk_auth_identifier,priority:2;default:''"`
	Identifier  string     `gorm:"column:identifier;type:varchar(255);uniqueIndex:uk_auth_identifier,priority:3"`
	Credential  *string    `gorm:"column:credential;type:varchar(255)"` // bcrypt hash; nullable for social login
	VerifiedAt  *time.Time `gorm:"column:verified_at"`
	LastUsedAt  *time.Time `gorm:"column:last_used_at"`
	Metadata    []byte     `gorm:"column:metadata;type:json"`
	CreatedAt   time.Time  `gorm:"column:created_at"`
	UpdatedAt   time.Time  `gorm:"column:updated_at"`
}

func (UserAuth) TableName() string { return "user_auth" }

// AuthType 常量。
const (
	AuthTypeUsername = "username"
	AuthTypeEmail    = "email"
	AuthTypePhone    = "phone"
	AuthTypeWxMini   = "wx_mini"
	AuthTypeWxWeb    = "wx_web"
	AuthTypeWxApp    = "wx_app"
	AuthTypeWxMP     = "wx_mp"
	AuthTypeWxUnion  = "wx_union"
	AuthTypeApple    = "apple"
	AuthTypeGoogle   = "google"
)
