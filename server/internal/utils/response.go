package utils

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrResp 是统一的错误响应结构（参考 OAuth 错误响应格式）。
type ErrResp struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// JSONError 写出统一格式的错误响应。
func JSONError(c *gin.Context, status int, code, description string) {
	c.AbortWithStatusJSON(status, ErrResp{
		Error:            code,
		ErrorDescription: description,
	})
}

// BadRequest 参数错误（400）。
func BadRequest(c *gin.Context, description string) {
	JSONError(c, http.StatusBadRequest, "invalid_request", description)
}

// Unauthorized 未认证（401）。
func Unauthorized(c *gin.Context, description string) {
	JSONError(c, http.StatusUnauthorized, "unauthorized", description)
}

// Forbidden 已认证但无权限（403）。
func Forbidden(c *gin.Context, description string) {
	JSONError(c, http.StatusForbidden, "forbidden", description)
}

// NotFound 资源不存在（404）。
func NotFound(c *gin.Context, description string) {
	JSONError(c, http.StatusNotFound, "not_found", description)
}

// Conflict 资源冲突（409）。
func Conflict(c *gin.Context, description string) {
	JSONError(c, http.StatusConflict, "conflict", description)
}

// TooManyRequests 限流命中（429）。
func TooManyRequests(c *gin.Context, description string) {
	JSONError(c, http.StatusTooManyRequests, "rate_limited", description)
}

// Internal 服务端错误（500）。
// 内部错误细节只写日志，不返回给客户端，避免暴露内部结构。
func Internal(c *gin.Context, internalErr error) {
	slog.Error("internal error",
		"path", c.Request.URL.Path,
		"method", c.Request.Method,
		"err", internalErr,
	)
	JSONError(c, http.StatusInternalServerError, "server_error", "internal server error")
}
