package middleware

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/utils"
)

// Recovery 捕获 panic，返回 500，避免进程挂掉。
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, err interface{}) {
		slog.Error("panic recovered", "err", err, "path", c.Request.URL.Path)
		utils.JSONError(c, http.StatusInternalServerError, "server_error", "internal server error")
	})
}
