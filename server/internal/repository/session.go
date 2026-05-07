package repository

import (
	"context"
	"time"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type SessionRepo struct{ db *gorm.DB }

func NewSessionRepo(db *gorm.DB) *SessionRepo { return &SessionRepo{db: db} }

func (r *SessionRepo) Create(ctx context.Context, s *model.UserSession) error {
	return r.db.WithContext(ctx).Create(s).Error
}

// FindByRefreshHash 按 refresh_token 哈希查找。
func (r *SessionRepo) FindByRefreshHash(ctx context.Context, hash string) (*model.UserSession, error) {
	var s model.UserSession
	if err := r.db.WithContext(ctx).
		Where("refresh_token_hash = ?", hash).
		First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

// MarkRotated 标记某 session 已被使用过（rotation 链中作废）。
func (r *SessionRepo) MarkRotated(ctx context.Context, id uint64) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.UserSession{}).
		Where("id = ?", id).
		Update("rotated_at", now).Error
}

// RevokeFamily 把整个 family 内所有 session 标记 revoked。
// 用于：refresh token 重放检测、用户登出（撤整条 rotation chain）。
func (r *SessionRepo) RevokeFamily(ctx context.Context, familyID string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.UserSession{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
}
