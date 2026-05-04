package repository

import (
	"context"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type OAuthClientRepo struct{ db *gorm.DB }

func NewOAuthClientRepo(db *gorm.DB) *OAuthClientRepo {
	return &OAuthClientRepo{db: db}
}

func (r *OAuthClientRepo) Create(ctx context.Context, c *model.OAuthClient) error {
	return r.db.WithContext(ctx).Create(c).Error
}

func (r *OAuthClientRepo) FindByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	var c model.OAuthClient
	if err := r.db.WithContext(ctx).
		Where("client_id = ? AND deleted = false AND status = ?", clientID, "active").
		First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *OAuthClientRepo) ExistsByClientID(ctx context.Context, clientID string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&model.OAuthClient{}).
		Where("client_id = ?", clientID).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
