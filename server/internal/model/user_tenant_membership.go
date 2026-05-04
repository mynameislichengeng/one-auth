package model

import "time"

// UserTenantMembership 用户-租户绑定关系（成员关系型多租户的核心表）。
// 简化设计（不实现邀请工作流）：状态只有 active / suspended，离开 = DELETE row。
type UserTenantMembership struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    uint64    `gorm:"column:user_id;uniqueIndex:uk_user_tenant,priority:1"`
	TenantID  uint64    `gorm:"column:tenant_id;uniqueIndex:uk_user_tenant,priority:2;index:idx_tenant_status,priority:1"`
	Status    string    `gorm:"column:status;type:varchar(20);default:active;index:idx_tenant_status,priority:2;index:idx_user_status,priority:2"`
	CreatedAt time.Time `gorm:"column:created_at;index:idx_user_status,priority:1"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (UserTenantMembership) TableName() string { return "user_tenant_memberships" }

const (
	MembershipStatusActive    = "active"
	MembershipStatusSuspended = "suspended"
)
