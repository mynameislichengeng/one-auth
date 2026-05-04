// Package service 业务逻辑层。封装多表事务、规则判断。
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

// 业务错误（service 层暴露给 handler 的语义错误）。
var (
	ErrInvalidCredential = errors.New("invalid credentials")
	ErrUserNotActive     = errors.New("user is not active")
	ErrIdentifierTaken   = errors.New("identifier already registered")
	ErrPasswordTooShort  = errors.New("password too short")
	ErrInvalidEmail      = errors.New("invalid email")
	ErrTokenInvalid      = errors.New("token invalid")
	ErrTokenReplay       = errors.New("refresh token replay detected")
	ErrTokenExpired      = errors.New("token expired")
	ErrTooManyAttempts   = errors.New("too many failed attempts; try later")
)

// AuthService 处理注册 / 登录 / 刷新 / 登出。
type AuthService struct {
	cfg         *config.Config
	db          *gorm.DB
	signer      *utils.JWTSigner
	users       *repository.UserRepo
	auths       *repository.UserAuthRepo
	memberships *repository.MembershipRepo
	tenants     *repository.TenantRepo
	sessions    *repository.SessionRepo
	blocklist   *repository.BlocklistRepo
	attempts    *repository.LoginAttemptRepo
}

func NewAuthService(
	cfg *config.Config,
	db *gorm.DB,
	signer *utils.JWTSigner,
	users *repository.UserRepo,
	auths *repository.UserAuthRepo,
	memberships *repository.MembershipRepo,
	tenants *repository.TenantRepo,
	sessions *repository.SessionRepo,
	blocklist *repository.BlocklistRepo,
	attempts *repository.LoginAttemptRepo,
) *AuthService {
	return &AuthService{
		cfg:         cfg,
		db:          db,
		signer:      signer,
		users:       users,
		auths:       auths,
		memberships: memberships,
		tenants:     tenants,
		sessions:    sessions,
		blocklist:   blocklist,
		attempts:    attempts,
	}
}

// TokenPair 是颁发给 client 的一对 token。
type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	TokenType        string    `json:"token_type"`           // "Bearer"
	ExpiresIn        int64     `json:"expires_in"`           // seconds
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
	IDToken          string    `json:"id_token,omitempty"`   // OIDC（scope 含 openid 时）
	Scope            string    `json:"scope,omitempty"`
	UserPublicID     string    `json:"user_id,omitempty"`
	TenantCode       string    `json:"tenant,omitempty"`
	Nickname         string    `json:"nickname,omitempty"`
}

// RegisterRequest 注册请求。V0.1 仅支持 email + password。
type RegisterRequest struct {
	Email    string
	Password string
	Nickname string
	IP       string
	UserAgent string
}

// Register 创建一个新用户，自动加入 main 租户，并直接颁发 token。
// 多表写入用事务保证一致性。
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*TokenPair, error) {
	if err := s.validatePassword(req.Password); err != nil {
		return nil, err
	}
	if err := s.validateEmail(req.Email); err != nil {
		return nil, err
	}

	// 提前查重，避免事务回滚噪音
	exists, err := s.auths.ExistsByIdentifier(ctx, model.AuthTypeEmail, req.Email)
	if err != nil {
		return nil, fmt.Errorf("check identifier: %w", err)
	}
	if exists {
		return nil, ErrIdentifierTaken
	}

	mainTenant, err := s.tenants.FindByCode(ctx, "main")
	if err != nil {
		return nil, fmt.Errorf("find main tenant: %w", err)
	}

	hash, err := utils.HashPassword(req.Password, s.cfg.Password.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now()
	user := &model.User{
		PublicID: utils.NewULID(),
		Nickname: req.Nickname,
		Status:   model.UserStatusActive,
	}
	if user.Nickname == "" {
		// 邮箱前缀作为默认昵称
		user.Nickname = strings.SplitN(req.Email, "@", 2)[0]
	}

	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 用 tx 重建 repo 以保证事务一致
		txUsers := repository.NewUserRepo(tx)
		txAuths := repository.NewUserAuthRepo(tx)
		txMembers := repository.NewMembershipRepo(tx)
		txSessions := repository.NewSessionRepo(tx)

		if err := txUsers.Create(ctx, user); err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		auth := &model.UserAuth{
			UserID:     user.ID,
			AuthType:   model.AuthTypeEmail,
			Identifier: req.Email,
			Credential: &hash,
			VerifiedAt: nil, // 邮箱未验证；后续可加邮箱验证流程
		}
		if err := txAuths.Create(ctx, auth); err != nil {
			return fmt.Errorf("create user_auth: %w", err)
		}

		mem := &model.UserTenantMembership{
			UserID:   user.ID,
			TenantID: mainTenant.ID,
			Status:   model.MembershipStatusActive,
		}
		if err := txMembers.Create(ctx, mem); err != nil {
			return fmt.Errorf("create membership: %w", err)
		}

		// 颁发 token
		var ie error
		pair, ie = s.issueTokens(ctx, txSessions, user, mainTenant, req.IP, req.UserAgent, now)
		return ie
	})
	if err != nil {
		return nil, err
	}
	return pair, nil
}

// LoginRequest 登录请求。
type LoginRequest struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

// Login 邮箱+密码登录。集成防爆破：
//  1. 检查同账号失败次数（窗口内 ≥ N 次直接拒绝）
//  2. 检查同 IP 失败次数
//  3. 每次尝试都写 login_attempts（成功/失败都记）
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*TokenPair, error) {
	if req.Email == "" || req.Password == "" {
		return nil, ErrInvalidCredential
	}

	now := time.Now()

	// 防爆破：账号级别窗口
	accWindow := now.Add(-s.cfg.RateLimit.LoginAccountWindow)
	if accFails, _ := s.attempts.CountFailuresByIdentifier(ctx,
		model.AuthTypeEmail, req.Email, accWindow); accFails >= int64(s.cfg.RateLimit.LoginAccountMaxFailures) {
		s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureLocked, nil)
		return nil, ErrTooManyAttempts
	}
	// 防爆破：IP 级别窗口
	ipWindow := now.Add(-s.cfg.RateLimit.LoginIPWindow)
	if ipFails, _ := s.attempts.CountFailuresByIP(ctx, req.IP, ipWindow); ipFails >= int64(s.cfg.RateLimit.LoginIPMaxFailures) {
		s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureLocked, nil)
		return nil, ErrTooManyAttempts
	}

	auth, err := s.auths.FindByIdentifier(ctx, model.AuthTypeEmail, req.Email)
	if err != nil {
		if repository.IsNotFound(err) {
			s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureUserNotFound, nil)
			// 不暴露"账号不存在"还是"密码错"，统一返回相同错误
			return nil, ErrInvalidCredential
		}
		return nil, err
	}
	if auth.Credential == nil || !utils.CheckPassword(req.Password, *auth.Credential) {
		s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureInvalidPassword, &auth.UserID)
		return nil, ErrInvalidCredential
	}

	user, err := s.users.FindByID(ctx, auth.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureUserSuspended, &user.ID)
		return nil, ErrUserNotActive
	}

	// V0.1 简化：只用 main 租户
	mainTenant, err := s.tenants.FindByCode(ctx, "main")
	if err != nil {
		return nil, err
	}
	hasMembership, err := s.memberships.ExistsActive(ctx, user.ID, mainTenant.ID)
	if err != nil {
		return nil, err
	}
	if !hasMembership {
		s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, false, model.LoginFailureUserSuspended, &user.ID)
		return nil, ErrUserNotActive
	}

	// 异步更新 last_used_at（失败不影响登录）
	_ = s.auths.MarkUsed(ctx, auth.ID)

	pair, err := s.issueTokens(ctx, s.sessions, user, mainTenant, req.IP, req.UserAgent, now)
	if err != nil {
		return nil, err
	}

	s.recordAttempt(ctx, req.Email, req.IP, req.UserAgent, true, "", &user.ID)
	return pair, nil
}

// recordAttempt 写一条登录尝试日志；失败不影响主链路（只记日志）。
func (s *AuthService) recordAttempt(ctx context.Context,
	identifier, ip, ua string, success bool, reason string, userID *uint64) {
	if err := s.attempts.Record(ctx, &model.LoginAttempt{
		AuthType:      model.AuthTypeEmail,
		Identifier:    identifier,
		IP:            ip,
		Success:       success,
		FailureReason: reason,
		UserAgent:     ua,
		UserID:        userID,
	}); err != nil {
		// 写审计日志失败不应阻塞登录，但要让运维看见
		slog.Error("login_attempts write failed",
			"err", err, "identifier", identifier, "success", success, "ip", ip)
	}
}

// Refresh 用 refresh_token 换新一对 token（含 rotation）。
// 重放检测：旧 refresh 再次使用 → 整 family 撤销。
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string) (*TokenPair, error) {
	hash := utils.HashRefreshToken(refreshToken)

	old, err := s.sessions.FindByRefreshHash(ctx, hash)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrTokenInvalid
		}
		return nil, err
	}

	now := time.Now()
	if old.ExpiresAt.Before(now) {
		return nil, ErrTokenExpired
	}
	if old.RevokedAt != nil {
		// 已撤销 → 攻击或异常
		return nil, ErrTokenInvalid
	}
	if old.RotatedAt != nil {
		// 旧 refresh 又被用了（重放）→ 整个 family 全部撤销
		_ = s.sessions.RevokeFamily(ctx, old.FamilyID)
		return nil, ErrTokenReplay
	}

	user, err := s.users.FindByID(ctx, old.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserNotActive
	}
	tenant, err := s.tenants.FindByID(ctx, old.TenantID)
	if err != nil {
		return nil, err
	}

	// 事务内：标 rotated + 创建新 session
	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txSessions := repository.NewSessionRepo(tx)
		if err := txSessions.MarkRotated(ctx, old.ID); err != nil {
			return err
		}
		// 复用 family_id，链接到 parent
		newRefresh, err := utils.RandomHex(32)
		if err != nil {
			return err
		}
		newSession := &model.UserSession{
			UserID:           user.ID,
			TenantID:         tenant.ID,
			ClientID:         old.ClientID,
			RefreshTokenHash: utils.HashRefreshToken(newRefresh),
			FamilyID:         old.FamilyID,
			ParentID:         &old.ID,
			DeviceType:       old.DeviceType,
			DeviceID:         old.DeviceID,
			UserAgent:        ua,
			IP:               ip,
			IssuedAt:         now,
			ExpiresAt:        now.Add(s.cfg.JWT.RefreshTokenTTL),
		}
		if err := txSessions.Create(ctx, newSession); err != nil {
			return err
		}

		access, _, err := s.signer.SignAccessToken(
			user.PublicID, tenant.Code, old.ClientID, newSession.FamilyID,
			[]string{}, s.cfg.JWT.AccessTokenTTL,
		)
		if err != nil {
			return err
		}

		pair = &TokenPair{
			AccessToken:      access,
			TokenType:        "Bearer",
			ExpiresIn:        int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
			RefreshToken:     newRefresh,
			RefreshExpiresAt: newSession.ExpiresAt,
			UserPublicID:     user.PublicID,
			TenantCode:       tenant.Code,
			Nickname:         user.Nickname,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pair, nil
}

// Logout 把当前 access_token 加入黑名单 + 撤销 session。
func (s *AuthService) Logout(ctx context.Context, claims *utils.Claims) error {
	now := time.Now()

	// 加 jwt 黑名单
	exp := claims.ExpiresAt.Time
	if exp.Before(now) {
		// 已过期，无需加黑名单
		return nil
	}

	uid, err := s.userIDFromClaims(ctx, claims)
	if err != nil {
		return err
	}

	if err := s.blocklist.Add(ctx, &model.JWTBlocklist{
		JTI:       claims.ID,
		UserID:    uid,
		Reason:    model.BlocklistReasonLogout,
		RevokedAt: now,
		ExpiresAt: exp,
	}); err != nil {
		return fmt.Errorf("blocklist add: %w", err)
	}

	// 撤销对应 session（family_id 维度——撤整条 rotation chain）
	if claims.SessionID != "" {
		_ = s.sessions.RevokeFamily(ctx, claims.SessionID)
	}
	return nil
}

// ----- helpers -----

func (s *AuthService) issueTokens(
	ctx context.Context, sessions *repository.SessionRepo,
	user *model.User, tenant *model.Tenant,
	ip, ua string, now time.Time,
) (*TokenPair, error) {
	clientID := "internal_v0_1" // V0.1 simplified login flow uses a placeholder client_id

	refreshRaw, err := utils.RandomHex(32)
	if err != nil {
		return nil, err
	}
	familyID := utils.NewULID()
	session := &model.UserSession{
		UserID:           user.ID,
		TenantID:         tenant.ID,
		ClientID:         clientID,
		RefreshTokenHash: utils.HashRefreshToken(refreshRaw),
		FamilyID:         familyID,
		UserAgent:        ua,
		IP:               ip,
		IssuedAt:         now,
		ExpiresAt:        now.Add(s.cfg.JWT.RefreshTokenTTL),
	}
	if err := sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	accessToken, _, err := s.signer.SignAccessToken(
		user.PublicID, tenant.Code, clientID, session.FamilyID,
		[]string{}, s.cfg.JWT.AccessTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	return &TokenPair{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        int64(s.cfg.JWT.AccessTokenTTL.Seconds()),
		RefreshToken:     refreshRaw,
		RefreshExpiresAt: session.ExpiresAt,
		UserPublicID:     user.PublicID,
		TenantCode:       tenant.Code,
		Nickname:         user.Nickname,
	}, nil
}

func (s *AuthService) userIDFromClaims(ctx context.Context, claims *utils.Claims) (uint64, error) {
	u, err := s.users.FindByPublicID(ctx, claims.Subject)
	if err != nil {
		return 0, err
	}
	return u.ID, nil
}

func (s *AuthService) validatePassword(p string) error {
	if len(p) < s.cfg.Password.MinLength {
		return ErrPasswordTooShort
	}
	return nil
}

func (s *AuthService) validateEmail(e string) error {
	// V0.1 简化校验：含 @ 即可。生产应换 net/mail 或 regex。
	if !strings.Contains(e, "@") || len(e) < 3 {
		return ErrInvalidEmail
	}
	return nil
}

// VerifyAccessToken 验签 + 检查黑名单。供 middleware 使用。
func (s *AuthService) VerifyAccessToken(ctx context.Context, token string) (*utils.Claims, error) {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	blocked, err := s.blocklist.IsBlocked(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

// GetUserByPublicID 给 handler 用。
func (s *AuthService) GetUserByPublicID(ctx context.Context, publicID string) (*model.User, error) {
	return s.users.FindByPublicID(ctx, publicID)
}
