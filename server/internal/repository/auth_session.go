package repository

import (
	"context"
	"time"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type AuthSessionRepo struct{ db *gorm.DB }

func NewAuthSessionRepo(db *gorm.DB) *AuthSessionRepo {
	return &AuthSessionRepo{db: db}
}

func (r *AuthSessionRepo) Create(ctx context.Context, s *model.AuthSession) error {
	return r.db.WithContext(ctx).Create(s).Error
}

// FindBySessionID 取一条非撤销、非过期的 session。
func (r *AuthSessionRepo) FindActiveBySessionID(ctx context.Context, sid string) (*model.AuthSession, error) {
	var s model.AuthSession
	if err := r.db.WithContext(ctx).
		Where("session_id = ? AND revoked_at IS NULL AND expires_at > NOW()", sid).
		First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

// Touch 更新 last_seen_at（成功认证时调）。
func (r *AuthSessionRepo) Touch(ctx context.Context, id uint64) error {
	return r.db.WithContext(ctx).
		Model(&model.AuthSession{}).
		Where("id = ?", id).
		Update("last_seen_at", time.Now()).Error
}

// Revoke 注销 session。
func (r *AuthSessionRepo) Revoke(ctx context.Context, sid string) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&model.AuthSession{}).
		Where("session_id = ? AND revoked_at IS NULL", sid).
		Update("revoked_at", now).Error
}
