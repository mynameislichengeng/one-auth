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
	"time"

	"github.com/licheng/oneauth/server/internal/cache"
	"github.com/licheng/oneauth/server/internal/config"
	"github.com/licheng/oneauth/server/internal/database"
	"github.com/licheng/oneauth/server/internal/migration"
	"github.com/licheng/oneauth/server/internal/repository"
	"github.com/licheng/oneauth/server/internal/server"
	"github.com/licheng/oneauth/server/internal/service"
	"github.com/licheng/oneauth/server/internal/utils"
	sqldata "github.com/licheng/oneauth/server/sql"
)

// Version / GitCommit / BuildTime 是构建期信息。
// build 时通过 ldflags 覆盖：
//   go build -ldflags "-X main.Version=$(git describe --tags) \
//                      -X main.GitCommit=$(git rev-parse --short HEAD) \
//                      -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	Version   = "v0.2.2"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "", "path to config file (default: config/config.${APP_ENV}.yaml)")
	flag.Parse()

	// 引导阶段：唯一一次直接读 APP_ENV 决定 configPath。
	// 业务代码之后只看 cfg.Env，不再 os.Getenv("APP_ENV")。
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "local"
	}

	resolvedPath := *configPath
	if resolvedPath == "" {
		resolvedPath = fmt.Sprintf("config/config.%s.yaml", appEnv)
	}

	if err := run(resolvedPath, appEnv); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, appEnv string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// 自检：APP_ENV（容器注入）和 yaml 里 env 字段必须一致，
	// 防止挂错 yaml / 环境变量错位等部署事故。
	if cfg.Env != appEnv {
		return fmt.Errorf("config env mismatch: APP_ENV=%s but %s declares env=%s",
			appEnv, configPath, cfg.Env)
	}

	// 元信息：启动时一次性注入到 cfg.Meta（不进 yaml）
	hostname, _ := os.Hostname()
	cfg.Meta = config.MetaInfo{
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		Hostname:  hostname,
		StartedAt: time.Now(),
	}

	setupLogger(cfg.Log)
	slog.Info("oneauth-server starting",
		"version", Version,
		"env", cfg.Env,
		"listen", cfg.Server.Listen,
		"git_commit", cfg.Meta.GitCommit,
	)

	// 数据库
	db, err := database.New(cfg.Database)
	if err != nil {
		return fmt.Errorf("init db: %w", err)
	}
	defer database.Close(db)

	// 自动 SQL 迁移（必须在 bootstrap 之前——bootstrap 依赖表已存在）。
	// 失败不阻塞启动；只记 slog.Error。开关由 migration.enabled 控制。
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sql.DB for migration: %w", err)
	}
	migration.Run(sqlDB, sqldata.UpdateFS(), cfg.Migration.Enabled)

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

	// HTTP server（cookie_secure / public_base_url 已经在 cfg.Server，
	// yaml 通过 ${COOKIE_SECURE} / ${PUBLIC_BASE_URL} 占位注入，业务层不再 os.Getenv）
	srv := server.New(server.Deps{
		Cfg:           cfg,
		DB:            db,
		Cache:         cacheImpl,
		AuthService:   authSvc,
		OAuthService:  oauthSvc,
		Blocklist:     blocklistRepo,
		BlocklistAdd:  blocklistRepo,
		CookieSecure:  cfg.Server.CookieSecure,
		PublicBaseURL: cfg.Server.PublicBaseURL,
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
