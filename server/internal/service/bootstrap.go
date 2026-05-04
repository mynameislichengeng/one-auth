package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/licheng/oneauth/server/internal/config"
	"github.com/licheng/oneauth/server/internal/model"
	"github.com/licheng/oneauth/server/internal/repository"
	"github.com/licheng/oneauth/server/internal/utils"
	"gorm.io/gorm"
)

// BootstrapResult 暴露给外层用（dev 期打印 admin_web 的 client_secret 给运维抄）。
type BootstrapResult struct {
	AdminWebClientID     string
	AdminWebClientSecret string // 仅当本次新建时返回；已有则为空
}

// EnsureBootstrap 启动时初始化数据：
//  1. 确保 main 租户存在
//  2. 如果 BOOTSTRAP_ENABLED=true 且管理员还不存在，则创建并绑定 platform_admin 角色
//  3. 确保默认 OAuth Client `admin_web` 存在（dev 期一次性打印 secret）
//
// 这是幂等的：重复调用不会重复创建；多实例并发启动时 duplicate key 转为"已存在"。
func EnsureBootstrap(ctx context.Context, cfg *config.Config, db *gorm.DB) (*BootstrapResult, error) {
	res := &BootstrapResult{}
	tenantsRepo := repository.NewTenantRepo(db)
	authsRepo := repository.NewUserAuthRepo(db)
	clientsRepo := repository.NewOAuthClientRepo(db)

	// Step 1：确保 main 租户存在（migration 应该已经种好，这里二次校验）
	mainTenant, err := tenantsRepo.FindByCode(ctx, "main")
	if err != nil {
		if !repository.IsNotFound(err) {
			return nil, fmt.Errorf("find main tenant: %w", err)
		}
		mainTenant = &model.Tenant{
			PublicID: utils.NewULID(),
			Code:     "main",
			Name:     "Platform",
			Type:     "platform",
			Status:   "active",
		}
		if err := db.WithContext(ctx).Create(mainTenant).Error; err != nil {
			// race condition：另一实例已创建 → 重新查
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				mainTenant, err = tenantsRepo.FindByCode(ctx, "main")
				if err != nil {
					return nil, fmt.Errorf("re-find main tenant after duplicate: %w", err)
				}
				slog.Info("bootstrap: main tenant created by another instance")
			} else {
				return nil, fmt.Errorf("create main tenant: %w", err)
			}
		} else {
			slog.Info("bootstrap: created main tenant", "id", mainTenant.ID)
		}
	}

	// Step 3：默认 OAuth Client `admin_web`（admin SPA 用）
	if err := ensureDefaultOAuthClients(ctx, db, clientsRepo, cfg, res); err != nil {
		return nil, err
	}

	// Step 2：bootstrap admin
	if !cfg.Bootstrap.Enabled {
		slog.Info("bootstrap admin disabled by config")
		return res, nil
	}
	if cfg.Bootstrap.AdminPassword == "" {
		slog.Warn("bootstrap admin password not set; skipping bootstrap admin creation")
		return res, nil
	}
	if !strings.Contains(cfg.Bootstrap.AdminEmail, "@") {
		return nil, fmt.Errorf("bootstrap admin email invalid: %q", cfg.Bootstrap.AdminEmail)
	}

	exists, err := authsRepo.ExistsByIdentifier(ctx, model.AuthTypeEmail, cfg.Bootstrap.AdminEmail)
	if err != nil {
		return nil, fmt.Errorf("check admin existence: %w", err)
	}
	if exists {
		slog.Info("bootstrap admin already exists, skipping")
		return res, nil
	}

	hash, err := utils.HashPassword(cfg.Bootstrap.AdminPassword, cfg.Password.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txUsers := repository.NewUserRepo(tx)
		txAuths := repository.NewUserAuthRepo(tx)
		txMembers := repository.NewMembershipRepo(tx)

		nick := cfg.Bootstrap.AdminNickname
		if nick == "" {
			nick = "Platform Admin"
		}
		u := &model.User{
			PublicID: utils.NewULID(),
			Nickname: nick,
			Status:   model.UserStatusActive,
		}
		if err := txUsers.Create(ctx, u); err != nil {
			return err
		}
		if err := txAuths.Create(ctx, &model.UserAuth{
			UserID:     u.ID,
			AuthType:   model.AuthTypeEmail,
			Identifier: cfg.Bootstrap.AdminEmail,
			Credential: &hash,
		}); err != nil {
			return err
		}
		if err := txMembers.Create(ctx, &model.UserTenantMembership{
			UserID:   u.ID,
			TenantID: mainTenant.ID,
			Status:   model.MembershipStatusActive,
		}); err != nil {
			return err
		}

		// 关键修复：绑定 platform_admin 角色（migration 已种好该角色和权限）
		if err := bindPlatformAdminRole(ctx, tx, u.ID, mainTenant.ID); err != nil {
			return fmt.Errorf("bind platform_admin role: %w", err)
		}

		slog.Info("bootstrap: created admin user with platform_admin role",
			"public_id", u.PublicID, "email", cfg.Bootstrap.AdminEmail)
		return nil
	})
	if err != nil {
		// 防止并发启动时双方都创建
		if !errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, fmt.Errorf("create bootstrap admin: %w", err)
		}
		slog.Info("bootstrap admin race-condition; another instance created it")
	}
	return res, nil
}

// bindPlatformAdminRole 把 platform_admin 角色授予 admin user。
// 不在事务里 select role_id 是因为系统角色 migration 已种入，肯定存在。
func bindPlatformAdminRole(ctx context.Context, tx *gorm.DB, userID, tenantID uint64) error {
	type roleRow struct{ ID uint64 }
	var r roleRow
	if err := tx.WithContext(ctx).
		Table("roles").
		Select("id").
		Where("code = ? AND is_system = TRUE", "platform_admin").
		Scan(&r).Error; err != nil {
		return err
	}
	if r.ID == 0 {
		return errors.New("platform_admin role not found; migration may have failed")
	}
	// user_roles 通过 (user_id, tenant_id, role_id, scope_type, scope_id) 唯一
	// 已存在则 INSERT IGNORE
	type userRoleRow struct {
		UserID    uint64    `gorm:"column:user_id"`
		TenantID  uint64    `gorm:"column:tenant_id"`
		RoleID    uint64    `gorm:"column:role_id"`
		ScopeType string    `gorm:"column:scope_type"`
		ScopeID   string    `gorm:"column:scope_id"`
		GrantedAt time.Time `gorm:"column:granted_at"`
	}
	row := userRoleRow{
		UserID:    userID,
		TenantID:  tenantID,
		RoleID:    r.ID,
		ScopeType: "",
		ScopeID:   "",
		GrantedAt: time.Now(),
	}
	err := tx.WithContext(ctx).Table("user_roles").Create(&row).Error
	if err != nil && errors.Is(err, gorm.ErrDuplicatedKey) {
		return nil // 已绑定
	}
	return err
}

// ensureDefaultOAuthClients 默认接入方：
//   - admin_web：oneauth admin SPA 自身（dogfooding）
//
// 已存在则跳过；不存在则创建并把 secret 写到 res 供启动日志一次性打印。
func ensureDefaultOAuthClients(
	ctx context.Context, db *gorm.DB, repo *repository.OAuthClientRepo,
	cfg *config.Config, res *BootstrapResult,
) error {
	const adminClientID = "admin_web"

	exists, err := repo.ExistsByClientID(ctx, adminClientID)
	if err != nil {
		return fmt.Errorf("check oauth_client existence: %w", err)
	}
	if exists {
		res.AdminWebClientID = adminClientID
		return nil
	}

	// 创建默认 admin_web client
	rawSecret, err := utils.RandomHex(24) // 48 字符 hex secret
	if err != nil {
		return err
	}
	hash, err := utils.HashPassword(rawSecret, cfg.Password.BcryptCost)
	if err != nil {
		return err
	}

	c := &model.OAuthClient{
		PublicID:               utils.NewULID(),
		ClientID:               adminClientID,
		ClientSecretHash:       hash,
		Name:                   "oneauth admin web",
		Description:            "oneauth 自带的管理后台（dogfooding）",
		ClientType:             model.ClientTypeFirstPartyConfidential,
		RedirectURIs:           model.JSONStrings{"http://localhost:8080/oauth/callback/admin"},
		GrantTypes:             model.JSONStrings{model.GrantTypeAuthorizationCode, model.GrantTypeRefreshToken},
		AllowedScopes:          model.JSONStrings{"openid", "profile", "email", "offline_access"},
		AllowedTenantTypes:     model.JSONStrings{"platform"},
		RequirePKCE:            true,
		AccessTokenTTLSeconds:  uint32(cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshTokenTTLSeconds: uint32(cfg.JWT.RefreshTokenTTL.Seconds()),
		Status:                 "active",
	}
	if err := repo.Create(ctx, c); err != nil {
		return fmt.Errorf("create admin_web client: %w", err)
	}

	slog.Warn("=========================================================")
	slog.Warn("bootstrap: created admin_web OAuth Client")
	slog.Warn("client_id     = " + c.ClientID)
	slog.Warn("client_secret = " + rawSecret + "  (SHOWN ONCE; save it now)")
	slog.Warn("redirect_uri  = " + c.RedirectURIs[0])
	slog.Warn("=========================================================")

	res.AdminWebClientID = c.ClientID
	res.AdminWebClientSecret = rawSecret
	return nil
}
