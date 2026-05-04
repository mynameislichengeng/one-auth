// Package middleware 提供通用 HTTP 中间件。
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/service"
	"github.com/licheng/oneauth/server/internal/utils"
)

// Context key 常量，用于在 handler 中取出 claims。
const (
	CtxClaimsKey = "auth.claims"
)

// AuthRequired 验证 Authorization: Bearer <token>。
// 验签通过且 jti 不在黑名单才放行。
func AuthRequired(svc *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			utils.Unauthorized(c, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(header, "Bearer ") {
			utils.Unauthorized(c, "Authorization header must start with 'Bearer '")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if token == "" {
			utils.Unauthorized(c, "missing bearer token")
			return
		}

		claims, err := svc.VerifyAccessToken(c.Request.Context(), token)
		if err != nil {
			utils.Unauthorized(c, "invalid or revoked token")
			return
		}

		c.Set(CtxClaimsKey, claims)
		c.Next()
	}
}

// ClaimsFrom 从 gin context 取出认证后的 claims。
func ClaimsFrom(c *gin.Context) *utils.Claims {
	v, ok := c.Get(CtxClaimsKey)
	if !ok {
		return nil
	}
	claims, _ := v.(*utils.Claims)
	return claims
}
