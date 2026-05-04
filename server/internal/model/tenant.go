package model

import "time"

// Tenant 租户。详见 03-data-model.md 1.1。
type Tenant struct {
	ID        uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	PublicID  string    `gorm:"column:public_id;type:char(26);uniqueIndex:uk_public_id"`
	Code      string    `gorm:"column:code;type:varchar(64);uniqueIndex:uk_code"`
	Name      string    `gorm:"column:name;type:varchar(200)"`
	Type      string    `gorm:"column:type;type:varchar(32)"` // platform/merchant/shop/...
	Status    string    `gorm:"column:status;type:varchar(20);default:active"`
	Settings  []byte    `gorm:"column:settings;type:json"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	CreatedBy *uint64   `gorm:"column:created_by"`
	UpdatedBy *uint64   `gorm:"column:updated_by"`
	Deleted   bool      `gorm:"column:deleted;default:false"`
}

func (Tenant) TableName() string { return "tenants" }
