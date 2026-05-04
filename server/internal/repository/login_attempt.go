package repository

import (
	"context"
	"time"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type LoginAttemptRepo struct{ db *gorm.DB }

func NewLoginAttemptRepo(db *gorm.DB) *LoginAttemptRepo {
	return &LoginAttemptRepo{db: db}
}

// Record 写入一条登录尝试日志。
// 失败不影响主流程（应用层应该忽略写入错误，避免审计写入失败导致登录无法进行）。
func (r *LoginAttemptRepo) Record(ctx context.Context, a *model.LoginAttempt) error {
	if a.AttemptedAt.IsZero() {
		a.AttemptedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(a).Error
}

// CountFailuresByIdentifier 统计某账号在窗口内的失败次数（防账号爆破）。
func (r *LoginAttemptRepo) CountFailuresByIdentifier(ctx context.Context,
	authType, identifier string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.LoginAttempt{}).
		Where("auth_type = ? AND identifier = ? AND success = false AND attempted_at >= ?",
			authType, identifier, since).
		Count(&count).Error
	return count, err
}

// CountFailuresByIP 统计某 IP 在窗口内的失败次数（防 IP 撞库）。
func (r *LoginAttemptRepo) CountFailuresByIP(ctx context.Context,
	ip string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.LoginAttempt{}).
		Where("ip = ? AND success = false AND attempted_at >= ?", ip, since).
		Count(&count).Error
	return count, err
}

// PurgeOlderThan cron 清理旧记录。
func (r *LoginAttemptRepo) PurgeOlderThan(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("attempted_at < ?", before).
		Delete(&model.LoginAttempt{})
	return res.RowsAffected, res.Error
}
