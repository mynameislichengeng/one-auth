// Package sql 嵌入 update/ 下所有 SQL 变更脚本，给 internal/migration 用。
//
// schema.sql 不被嵌入——它只是当前完整表结构的开发者参考，由开发者手动维护，
// 不参与运行时自动迁移。
//
// "all:" 前缀允许嵌入点前缀文件（.gitkeep 等），避免空目录启动时报
// "no embeddable files"。
package sql

import (
	"embed"
	"io/fs"
)

//go:embed all:update
var updateFS embed.FS

// UpdateFS 返回 update/ 下的子文件系统，给 internal/migration 用。
func UpdateFS() fs.FS {
	sub, _ := fs.Sub(updateFS, "update")
	return sub
}
