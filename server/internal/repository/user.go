package repository

import (
	"context"

	"github.com/licheng/oneauth/server/internal/model"
	"gorm.io/gorm"
)

type UserRepo struct{ db *gorm.DB }

func NewUserRepo(db *gorm.DB) *UserRepo { return &UserRepo{db: db} }

func (r *UserRepo) Create(ctx context.Context, u *model.User) error {
	return r.db.WithContext(ctx).Create(u).Error
}

func (r *UserRepo) FindByID(ctx context.Context, id uint64) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).
		Where("id = ? AND deleted = false", id).
		First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) FindByPublicID(ctx context.Context, publicID string) (*model.User, error) {
	var u model.User
	if err := r.db.WithContext(ctx).
		Where("public_id = ? AND deleted = false", publicID).
		First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}
