package repository

import (
	"context"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type TenantRepo struct{ db *gorm.DB }

func NewTenantRepo(db *gorm.DB) *TenantRepo { return &TenantRepo{db: db} }

func (r *TenantRepo) FindByCode(ctx context.Context, code string) (*model.Tenant, error) {
	var t model.Tenant
	if err := r.db.WithContext(ctx).
		Where("code = ? AND deleted = false", code).
		First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TenantRepo) FindByID(ctx context.Context, id uint64) (*model.Tenant, error) {
	var t model.Tenant
	if err := r.db.WithContext(ctx).
		Where("id = ? AND deleted = false", id).
		First(&t).Error; err != nil {
		return nil, err
	}
	return &t, nil
}
