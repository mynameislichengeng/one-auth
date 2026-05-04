package repository

import (
	"context"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type MembershipRepo struct{ db *gorm.DB }

func NewMembershipRepo(db *gorm.DB) *MembershipRepo { return &MembershipRepo{db: db} }

func (r *MembershipRepo) Create(ctx context.Context, m *model.UserTenantMembership) error {
	return r.db.WithContext(ctx).Create(m).Error
}

// ListActiveTenants 返回该 user 加入的所有 active tenant 行（按 tenant id 排序）。
func (r *MembershipRepo) ListActiveTenants(ctx context.Context, userID uint64) ([]model.Tenant, error) {
	var tenants []model.Tenant
	err := r.db.WithContext(ctx).
		Table("tenants t").
		Joins("INNER JOIN user_tenant_memberships m ON m.tenant_id = t.id").
		Where("m.user_id = ? AND m.status = ? AND t.deleted = false", userID, model.MembershipStatusActive).
		Order("t.id ASC").
		Scan(&tenants).Error
	return tenants, err
}

// ExistsActive 检查 (user, tenant) 是否有 active membership。
func (r *MembershipRepo) ExistsActive(ctx context.Context, userID, tenantID uint64) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.UserTenantMembership{}).
		Where("user_id = ? AND tenant_id = ? AND status = ?", userID, tenantID, model.MembershipStatusActive).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
