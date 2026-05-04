// Package repository 封装数据访问。每个 repo 只负责单表 CRUD，跨表事务在 service 层组合。
package repository

import (
	"errors"

	"gorm.io/gorm"
)

// IsNotFound 判断 GORM 错误是否为"记录不存在"。
func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
