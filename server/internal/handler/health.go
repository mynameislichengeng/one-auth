// Package handler HTTP 处理层。
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/cache"
	"github.com/licheng/oneauth/server/internal/database"
	"gorm.io/gorm"
)

// HealthHandler 实现 /health 和 /ready。
type HealthHandler struct {
	db    *gorm.DB
	cache cache.Cache
}

func NewHealthHandler(db *gorm.DB, c cache.Cache) *HealthHandler {
	return &HealthHandler{db: db, cache: c}
}

// Live 进程存活探针：只要 server 在跑就返回 200。
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Ready 就绪探针：DB 和（如启用 Redis）Redis 连通才返回 200。
func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := database.Ping(ctx, h.db); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"reason": "database unreachable",
		})
		return
	}

	// 仅 RedisCache 实现支持 Ping；MemoryCache 跳过
	if pinger, ok := h.cache.(interface{ Ping(context.Context) error }); ok {
		if err := pinger.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"reason": "cache unreachable",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
