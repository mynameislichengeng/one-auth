// Package cache 定义临时 KV 数据的抽象（D-F1）。
//
// 设计原则：
//   - 接口刻意精简，只暴露 Set/Get/Delete，不泄露 Redis 特有 API（INCR、Lua 等）。
//   - 实现：MemoryCache（dev 友好）、RedisCache（生产默认）。
//   - 通过配置切换 driver=memory|redis，应用层零改动。
//
// 不要把以下数据塞进 Cache：
//   - Session（auth_sessions / user_sessions）→ MySQL，不能丢
//   - JWT 黑名单 → MySQL
//   - 限流计数 → 单独抽象 RateLimiter
package cache

import (
	"context"
	"errors"
	"time"

	"github.com/licheng/oneauth/server/internal/config"
)

// ErrNotFound 表示 key 不存在或已过期。
var ErrNotFound = errors.New("cache: not found")

// Cache 是临时 KV 存储的统一接口。
type Cache interface {
	// Set 写入 key=value，过期时间 ttl。
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Get 读取；不存在返回 ErrNotFound。
	Get(ctx context.Context, key string) ([]byte, error)
	// Delete 删除 key（不存在不报错）。
	Delete(ctx context.Context, key string) error
	// Close 释放底层资源。
	Close() error
}

// New 按配置创建 Cache 实例。
func New(cfg config.CacheConfig) (Cache, error) {
	switch cfg.Driver {
	case "redis":
		return NewRedisCache(cfg.Redis)
	case "memory":
		return NewMemoryCache(cfg.Memory), nil
	default:
		return nil, errors.New("unknown cache driver: " + cfg.Driver)
	}
}
