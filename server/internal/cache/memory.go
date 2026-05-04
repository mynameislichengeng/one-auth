package cache

import (
	"context"
	"time"

	"github.com/licheng/oneauth/server/internal/config"
	gocache "github.com/patrickmn/go-cache"
)

// MemoryCache 进程内缓存（适合 dev、单元测试、单实例小规模部署）。
type MemoryCache struct {
	c *gocache.Cache
}

// NewMemoryCache 用 patrickmn/go-cache 实现。
func NewMemoryCache(cfg config.CacheMemoryConfig) *MemoryCache {
	return &MemoryCache{
		c: gocache.New(cfg.DefaultTTL, cfg.CleanupInterval),
	}
}

func (m *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.c.Set(key, value, ttl)
	return nil
}

func (m *MemoryCache) Get(_ context.Context, key string) ([]byte, error) {
	v, found := m.c.Get(key)
	if !found {
		return nil, ErrNotFound
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, ErrNotFound
	}
	// 拷贝一份，避免调用方修改影响缓存
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (m *MemoryCache) Delete(_ context.Context, key string) error {
	m.c.Delete(key)
	return nil
}

func (m *MemoryCache) Close() error {
	m.c.Flush()
	return nil
}
