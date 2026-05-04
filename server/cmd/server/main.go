// oneauth-server 启动入口。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/licheng/oneauth/server/internal/cache"
	"github.com/licheng/oneauth/server/internal/config"
	"github.com/licheng/oneauth/server/internal/database"
	"github.com/licheng/oneauth/server/internal/repository"
	"github.com/licheng/oneauth/server/internal/server"
	"github.com/licheng/oneauth/server/internal/service"
	"github.com/licheng/oneauth/server/internal/utils"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	setupLogger(cfg.Log)
	slog.Info("oneauth-server starting", "version", "v0.1.0", "listen", cfg.Server.Listen)

	// 数据库
	db, err := database.New(cfg.Database)
	if err != nil {
		return fmt.Errorf("init db: %w", err)
	}
	defer database.Close(db)

	// 缓存
	cacheImpl, err := cache.New(cfg.Cache)
	if err != nil {
		return fmt.Errorf("init cache: %w", err)
	}
	defer cacheImpl.Close()
	slog.Info("cache initialized", "driver", cfg.Cache.Driver)

	// JWT 签名器（首次启动会自动生成 RSA 密钥对）
	signer, err := utils.NewJWTSigner(
		cfg.JWT.PrivateKeyPath, cfg.JWT.PublicKeyPath,
		cfg.JWT.Issuer, cfg.JWT.Algorithm,
	)
	if err != nil {
		return fmt.Errorf("init jwt signer: %w", err)
	}
	slog.Info("jwt signer ready", "alg", cfg.JWT.Algorithm)

	// Repos
	tenantRepo := repository.NewTenantRepo(db)
	userRepo := repository.NewUserRepo(db)
	authRepo := repository.NewUserAuthRepo(db)
	membershipRepo := repository.NewMembershipRepo(db)
	sessionRepo := repository.NewSessionRepo(db)
	blocklistRepo := repository.NewBlocklistRepo(db)
	loginAttemptRepo := repository.NewLoginAttemptRepo(db)
	oauthClientRepo := repository.NewOAuthClientRepo(db)
	authSessionRepo := repository.NewAuthSessionRepo(db)

	// Bootstrap（创建 main 租户、默认管理员、默认 OAuth Client，幂等）
	bootstrapCtx, bootstrapCancel := context.WithTimeout(context.Background(), cfg.Server.ReadTimeout*3)
	if _, err := service.EnsureBootstrap(bootstrapCtx, cfg, db); err != nil {
		bootstrapCancel()
		return fmt.Errorf("bootstrap: %w", err)
	}
	bootstrapCancel()

	authSvc := service.NewAuthService(
		cfg, db, signer,
		userRepo, authRepo, membershipRepo, tenantRepo,
		sessionRepo, blocklistRepo, loginAttemptRepo,
	)

	oauthSvc := service.NewOAuthService(
		cfg, db, signer, cacheImpl,
		oauthClientRepo, userRepo, authRepo, tenantRepo,
		sessionRepo, authSessionRepo, membershipRepo,
	)

	// dev 期 HTTP，Secure cookie 必须 false 浏览器才接受
	cookieSecure := os.Getenv("COOKIE_SECURE") == "true"
	// OIDC discovery 用的 issuer URL；dev 期默认从 Host 头推断
	publicBaseURL := os.Getenv("PUBLIC_BASE_URL")

	// HTTP server
	srv := server.New(server.Deps{
		Cfg:           cfg,
		DB:            db,
		Cache:         cacheImpl,
		AuthService:   authSvc,
		OAuthService:  oauthSvc,
		Blocklist:     blocklistRepo,
		BlocklistAdd:  blocklistRepo,
		CookieSecure:  cookieSecure,
		PublicBaseURL: publicBaseURL,
	})

	// 信号处理（优雅关闭）
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := server.Run(ctx, srv, cfg.Server.ShutdownTimeout); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

func setupLogger(cfg config.LogConfig) {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.Format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}
