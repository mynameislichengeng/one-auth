package repository

import (
	"context"
	"time"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type UserAuthRepo struct{ db *gorm.DB }

func NewUserAuthRepo(db *gorm.DB) *UserAuthRepo { return &UserAuthRepo{db: db} }

func (r *UserAuthRepo) Create(ctx context.Context, ua *model.UserAuth) error {
	return r.db.WithContext(ctx).Create(ua).Error
}

// FindByIdentifier 按 (auth_type, identifier) 查找；auth_source 默认空字符串。
// 这是登录主链路最关键的查询。
func (r *UserAuthRepo) FindByIdentifier(ctx context.Context, authType, identifier string) (*model.UserAuth, error) {
	var ua model.UserAuth
	if err := r.db.WithContext(ctx).
		Where("auth_type = ? AND auth_source = ? AND identifier = ?", authType, "", identifier).
		First(&ua).Error; err != nil {
		return nil, err
	}
	return &ua, nil
}

// MarkUsed 更新 last_used_at。失败不影响主链路。
func (r *UserAuthRepo) MarkUsed(ctx context.Context, id uint64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.UserAuth{}).
		Where("id = ?", id).
		Update("last_used_at", now).Error
}

// ExistsByIdentifier 仅检查存在，避免取整行。
func (r *UserAuthRepo) ExistsByIdentifier(ctx context.Context, authType, identifier string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.UserAuth{}).
		Where("auth_type = ? AND auth_source = ? AND identifier = ?", authType, "", identifier).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
