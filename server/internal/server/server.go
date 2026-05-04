// Package server 路由注册和 HTTP server 生命周期。
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/cache"
	"github.com/licheng/oneauth/server/internal/config"
	"github.com/licheng/oneauth/server/internal/handler"
	"github.com/licheng/oneauth/server/internal/middleware"
	"github.com/licheng/oneauth/server/internal/service"
	"gorm.io/gorm"
)

type Deps struct {
	Cfg          *config.Config
	DB           *gorm.DB
	Cache        cache.Cache
	AuthService  *service.AuthService
	OAuthService *service.OAuthService
	CookieSecure bool
}

// New 构造路由 + HTTP server。
func New(deps Deps) *http.Server {
	if deps.Cfg.Log.Level == "info" || deps.Cfg.Log.Level == "warn" || deps.Cfg.Log.Level == "error" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(middleware.Recovery(), middleware.AccessLog())

	healthH := handler.NewHealthHandler(deps.DB, deps.Cache)
	authH := handler.NewAuthHandler(deps.AuthService)
	oauthH := handler.NewOAuthHandler(deps.OAuthService, deps.AuthService, deps.CookieSecure)

	// 健康检查（无需鉴权）
	r.GET("/health", healthH.Live)
	r.GET("/ready", healthH.Ready)

	// OAuth 协议端点（V0.2）
	r.GET("/oauth/authorize", oauthH.Authorize)
	r.POST("/oauth/token", oauthH.Token)

	// 登录页（HTML 表单）+ OAuth 域 logout
	r.GET("/login", oauthH.GetLogin)
	r.POST("/login", oauthH.PostLogin)
	r.GET("/logout", oauthH.Logout)

	// V0.1 简化 API（保留兼容，方便 e2e 测试与迁移）
	api := r.Group("/api")
	{
		api.POST("/auth/register", authH.Register)
		api.POST("/auth/login", authH.Login)
		api.POST("/auth/refresh", authH.Refresh)

		// 受保护
		authed := api.Group("")
		authed.Use(middleware.AuthRequired(deps.AuthService))
		authed.POST("/auth/logout", authH.Logout)
		authed.GET("/me", authH.Me)
	}

	return &http.Server{
		Addr:         deps.Cfg.Server.Listen,
		Handler:      r,
		ReadTimeout:  deps.Cfg.Server.ReadTimeout,
		WriteTimeout: deps.Cfg.Server.WriteTimeout,
	}
}

// Run 启动 server，监听信号优雅关闭。
func Run(ctx context.Context, srv *http.Server, shutdownTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down http server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "err", err)
			return err
		}
		slog.Info("http server stopped cleanly")
		return nil
	}
}
