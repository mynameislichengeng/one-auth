package repository

import (
	"context"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type BlocklistRepo struct{ db *gorm.DB }

func NewBlocklistRepo(db *gorm.DB) *BlocklistRepo { return &BlocklistRepo{db: db} }

// Add 把 jti 加入黑名单。
func (r *BlocklistRepo) Add(ctx context.Context, e *model.JWTBlocklist) error {
	return r.db.WithContext(ctx).Create(e).Error
}

// IsBlocked 查 jti 是否在黑名单（已撤销 token 检查的关键路径）。
func (r *BlocklistRepo) IsBlocked(ctx context.Context, jti string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.JWTBlocklist{}).
		Where("jti = ?", jti).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// PurgeExpired cron 清理过期黑名单条目。
func (r *BlocklistRepo) PurgeExpired(ctx context.Context) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expires_at < NOW()").
		Delete(&model.JWTBlocklist{})
	return res.RowsAffected, res.Error
}
