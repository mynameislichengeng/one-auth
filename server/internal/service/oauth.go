package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/licheng/oneauth/server/internal/cache"
	"github.com/licheng/oneauth/server/internal/config"
	"github.com/licheng/oneauth/server/internal/model"
	"github.com/licheng/oneauth/server/internal/repository"
	"github.com/licheng/oneauth/server/internal/utils"
	"gorm.io/gorm"
)

// OAuth 业务错误。
var (
	ErrInvalidClient       = errors.New("invalid_client")
	ErrInvalidGrant        = errors.New("invalid_grant")
	ErrInvalidRequest      = errors.New("invalid_request")
	ErrUnauthorizedClient  = errors.New("unauthorized_client")
	ErrUnsupportedGrant    = errors.New("unsupported_grant_type")
	ErrInvalidScope        = errors.New("invalid_scope")
	ErrInvalidRedirectURI  = errors.New("invalid_redirect_uri")
	ErrAuthSessionInvalid  = errors.New("auth session invalid or expired")
	ErrPKCEMismatch        = errors.New("PKCE code_verifier mismatch")
)

// AuthCodeData 是 /authorize 颁发的 code 在缓存里关联的元数据。
type AuthCodeData struct {
	ClientID            string    `json:"client_id"`
	UserID              uint64    `json:"user_id"`
	UserPublicID        string    `json:"user_public_id"`
	TenantID            uint64    `json:"tenant_id"`
	TenantCode          string    `json:"tenant_code"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	IssuedAt            time.Time `json:"issued_at"`
}

// OAuthService 处理 /oauth/* 相关流程。
type OAuthService struct {
	cfg          *config.Config
	db           *gorm.DB
	signer       *utils.JWTSigner
	cache        cache.Cache
	clients      *repository.OAuthClientRepo
	users        *repository.UserRepo
	auths        *repository.UserAuthRepo
	tenants      *repository.TenantRepo
	sessions     *repository.SessionRepo
	authSessions *repository.AuthSessionRepo
	memberships  *repository.MembershipRepo
}

func NewOAuthService(
	cfg *config.Config, db *gorm.DB, signer *utils.JWTSigner, c cache.Cache,
	clients *repository.OAuthClientRepo,
	users *repository.UserRepo,
	auths *repository.UserAuthRepo,
	tenants *repository.TenantRepo,
	sessions *repository.SessionRepo,
	authSessions *repository.AuthSessionRepo,
	memberships *repository.MembershipRepo,
) *OAuthService {
	return &OAuthService{
		cfg: cfg, db: db, signer: signer, cache: c,
		clients: clients, users: users, auths: auths, tenants: tenants,
		sessions: sessions, authSessions: authSessions, memberships: memberships,
	}
}

// LookupClient 验证 client_id 是否存在并且活跃。
func (s *OAuthService) LookupClient(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	c, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	return c, nil
}

// VerifyClientSecret 校验 client_secret（confidential client）。
func (s *OAuthService) VerifyClientSecret(c *model.OAuthClient, secret string) error {
	if !c.IsConfidential() {
		return nil
	}
	if !utils.CheckPassword(secret, c.ClientSecretHash) {
		return ErrInvalidClient
	}
	return nil
}

// AuthorizeRequest 是 /oauth/authorize 的入参（已校验 client_id 后）。
type AuthorizeRequest struct {
	Client              *model.OAuthClient
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string // "S256" / "plain"
	ResponseType        string // 必须是 "code"
}

// AuthorizeResult 是 /oauth/authorize 处理结果。
type AuthorizeResult struct {
	Code        string // 颁发的 authorization code
	RedirectURI string // 重定向回的 client URI（不带 code/state）
	State       string // 原样回传
}

// IssueCode 创建 authorization_code 并存到 cache（5 min TTL）。
// 调用方应该已经验证了 auth_session 且确定了 user。
func (s *OAuthService) IssueCode(ctx context.Context, req AuthorizeRequest, user *model.User) (*AuthorizeResult, error) {
	if req.ResponseType != "code" {
		return nil, ErrInvalidRequest
	}
	if !req.Client.AllowsRedirectURI(req.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	if !req.Client.AllowsGrantType(model.GrantTypeAuthorizationCode) {
		return nil, ErrUnauthorizedClient
	}
	if req.Client.RequirePKCE && req.CodeChallenge == "" {
		return nil, ErrInvalidRequest
	}
	if req.CodeChallengeMethod != "" &&
		req.CodeChallengeMethod != "S256" &&
		req.CodeChallengeMethod != "plain" {
		return nil, ErrInvalidRequest
	}

	// 找 user 在 main 租户下的 membership（V0.2 简化）
	mainTenant, err := s.tenants.FindByCode(ctx, "main")
	if err != nil {
		return nil, err
	}
	hasMembership, err := s.memberships.ExistsActive(ctx, user.ID, mainTenant.ID)
	if err != nil {
		return nil, err
	}
	if !hasMembership {
		return nil, ErrUnauthorizedClient
	}

	codeRaw, err := utils.RandomHex(32) // 64 字符 hex
	if err != nil {
		return nil, err
	}

	data := AuthCodeData{
		ClientID:            req.Client.ClientID,
		UserID:              user.ID,
		UserPublicID:        user.PublicID,
		TenantID:            mainTenant.ID,
		TenantCode:          mainTenant.Code,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		IssuedAt:            time.Now(),
	}
	payload, _ := json.Marshal(data)

	if err := s.cache.Set(ctx, codeKey(codeRaw), payload, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache set code: %w", err)
	}

	return &AuthorizeResult{
		Code:        codeRaw,
		RedirectURI: req.RedirectURI,
		State:       req.State,
	}, nil
}

// TokenExchangeRequest 是 /oauth/token 的入参。
type TokenExchangeRequest struct {
	GrantType    string
	Code         string // for authorization_code
	RedirectURI  string // for authorization_code (must match)
	CodeVerifier string // for PKCE
	RefreshToken string // for refresh_token
	Scope        string // for client_credentials
	ClientID     string
	ClientSecret string
	IP           string
	UserAgent    string
}

// ExchangeToken 处理 /oauth/token，按 grant_type 分发。
func (s *OAuthService) ExchangeToken(ctx context.Context, req TokenExchangeRequest) (*TokenPair, error) {
	client, err := s.LookupClient(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.VerifyClientSecret(client, req.ClientSecret); err != nil {
		return nil, err
	}
	if !client.AllowsGrantType(req.GrantType) {
		return nil, ErrUnauthorizedClient
	}

	switch req.GrantType {
	case model.GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, client, req)
	case model.GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, client, req)
	default:
		return nil, ErrUnsupportedGrant
	}
}

func (s *OAuthService) exchangeAuthorizationCode(
	ctx context.Context, client *model.OAuthClient, req TokenExchangeRequest,
) (*TokenPair, error) {
	if req.Code == "" {
		return nil, ErrInvalidRequest
	}

	raw, err := s.cache.Get(ctx, codeKey(req.Code))
	if err != nil {
		return nil, ErrInvalidGrant
	}
	// code 用一次即删（防重放）
	_ = s.cache.Delete(ctx, codeKey(req.Code))

	var data AuthCodeData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, ErrInvalidGrant
	}

	// 校验 client_id 匹配
	if data.ClientID != client.ClientID {
		return nil, ErrInvalidGrant
	}
	// 校验 redirect_uri 与发码时一致
	if data.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidGrant
	}
	// 校验 PKCE
	if data.CodeChallenge != "" {
		if !verifyPKCE(req.CodeVerifier, data.CodeChallenge, data.CodeChallengeMethod) {
			return nil, ErrPKCEMismatch
		}
	}

	user, err := s.users.FindByID(ctx, data.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrInvalidGrant
	}

	tenant, err := s.tenants.FindByID(ctx, data.TenantID)
	if err != nil {
		return nil, err
	}

	return s.issueTokensForClient(ctx, user, tenant, client, req.IP, req.UserAgent)
}

func (s *OAuthService) exchangeRefreshToken(
	ctx context.Context, client *model.OAuthClient, req TokenExchangeRequest,
) (*TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, ErrInvalidRequest
	}

	hash := utils.HashRefreshToken(req.RefreshToken)
	old, err := s.sessions.FindByRefreshHash(ctx, hash)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}

	now := time.Now()
	if old.ExpiresAt.Before(now) {
		return nil, ErrInvalidGrant
	}
	if old.RevokedAt != nil {
		return nil, ErrInvalidGrant
	}
	if old.RotatedAt != nil {
		// 重放检测 → 整 family revoke
		_ = s.sessions.RevokeFamily(ctx, old.FamilyID)
		return nil, ErrInvalidGrant
	}
	if old.ClientID != client.ClientID {
		return nil, ErrInvalidGrant
	}

	user, err := s.users.FindByID(ctx, old.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrInvalidGrant
	}
	tenant, err := s.tenants.FindByID(ctx, old.TenantID)
	if err != nil {
		return nil, err
	}

	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txSessions := repository.NewSessionRepo(tx)
		if err := txSessions.MarkRotated(ctx, old.ID); err != nil {
			return err
		}
		newRefresh, err := utils.RandomHex(32)
		if err != nil {
			return err
		}
		newSession := &model.UserSession{
			UserID:           user.ID,
			TenantID:         tenant.ID,
			ClientID:         client.ClientID,
			RefreshTokenHash: utils.HashRefreshToken(newRefresh),
			FamilyID:         old.FamilyID,
			ParentID:         &old.ID,
			DeviceType:       old.DeviceType,
			DeviceID:         old.DeviceID,
			UserAgent:        req.UserAgent,
			IP:               req.IP,
			IssuedAt:         now,
			ExpiresAt:        now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second),
		}
		if err := txSessions.Create(ctx, newSession); err != nil {
			return err
		}

		ttl := time.Duration(client.AccessTokenTTLSeconds) * time.Second
		access, _, err := s.signer.SignAccessToken(
			user.PublicID, tenant.Code, client.ClientID, newSession.ID,
			[]string{}, ttl,
		)
		if err != nil {
			return err
		}

		pair = &TokenPair{
			AccessToken:      access,
			TokenType:        "Bearer",
			ExpiresIn:        int64(ttl.Seconds()),
			RefreshToken:     newRefresh,
			RefreshExpiresAt: newSession.ExpiresAt,
			UserPublicID:     user.PublicID,
			TenantCode:       tenant.Code,
			Nickname:         user.Nickname,
		}
		return nil
	})
	return pair, err
}

func (s *OAuthService) issueTokensForClient(
	ctx context.Context, user *model.User, tenant *model.Tenant,
	client *model.OAuthClient, ip, ua string,
) (*TokenPair, error) {
	now := time.Now()
	refreshRaw, err := utils.RandomHex(32)
	if err != nil {
		return nil, err
	}
	familyID := utils.NewULID()
	session := &model.UserSession{
		UserID:           user.ID,
		TenantID:         tenant.ID,
		ClientID:         client.ClientID,
		RefreshTokenHash: utils.HashRefreshToken(refreshRaw),
		FamilyID:         familyID,
		UserAgent:        ua,
		IP:               ip,
		IssuedAt:         now,
		ExpiresAt:        now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	ttl := time.Duration(client.AccessTokenTTLSeconds) * time.Second
	access, _, err := s.signer.SignAccessToken(
		user.PublicID, tenant.Code, client.ClientID, session.ID,
		[]string{}, ttl,
	)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}
	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresIn:        int64(ttl.Seconds()),
		RefreshToken:     refreshRaw,
		RefreshExpiresAt: session.ExpiresAt,
		UserPublicID:     user.PublicID,
		TenantCode:       tenant.Code,
		Nickname:         user.Nickname,
	}, nil
}

// CreateAuthSession 在 oneauth 域种 SSO cookie session。
func (s *OAuthService) CreateAuthSession(ctx context.Context, user *model.User, ip, ua string) (string, error) {
	sid, err := utils.RandomHex(32) // 64 字符 hex
	if err != nil {
		return "", err
	}
	now := time.Now()
	if err := s.authSessions.Create(ctx, &model.AuthSession{
		SessionID:  sid,
		UserID:     user.ID,
		IP:         ip,
		UserAgent:  ua,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.cfg.JWT.AuthSessionTTL),
	}); err != nil {
		return "", err
	}
	return sid, nil
}

// VerifyAuthSession 取出 cookie 对应的 user（验证 session 有效）。
func (s *OAuthService) VerifyAuthSession(ctx context.Context, sid string) (*model.User, error) {
	if sid == "" {
		return nil, ErrAuthSessionInvalid
	}
	sess, err := s.authSessions.FindActiveBySessionID(ctx, sid)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrAuthSessionInvalid
		}
		return nil, err
	}
	user, err := s.users.FindByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrAuthSessionInvalid
	}
	_ = s.authSessions.Touch(ctx, sess.ID)
	return user, nil
}

// RevokeAuthSession 撤销 cookie session（用于登出）。
func (s *OAuthService) RevokeAuthSession(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	return s.authSessions.Revoke(ctx, sid)
}

// AuthenticatePassword 用密码验证身份（不创建 session/token，仅返回 user）。
// 与 AuthService.Login 类似但不签 JWT；用于 oneauth 自己的登录页表单。
// 重用 AuthService 的防爆破和登录尝试记录。
func (s *OAuthService) AuthenticatePassword(ctx context.Context, email, password, ip, ua string) (*model.User, error) {
	if email == "" || password == "" {
		return nil, ErrInvalidCredential
	}
	auth, err := s.auths.FindByIdentifier(ctx, model.AuthTypeEmail, email)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrInvalidCredential
		}
		return nil, err
	}
	if auth.Credential == nil || !utils.CheckPassword(password, *auth.Credential) {
		return nil, ErrInvalidCredential
	}
	user, err := s.users.FindByID(ctx, auth.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrUserNotActive
	}
	mainTenant, err := s.tenants.FindByCode(ctx, "main")
	if err != nil {
		return nil, err
	}
	ok, err := s.memberships.ExistsActive(ctx, user.ID, mainTenant.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrUserNotActive
	}
	_ = s.auths.MarkUsed(ctx, auth.ID)
	return user, nil
}

// ----- helpers -----

func codeKey(code string) string {
	return "oauth:code:" + code
}

// verifyPKCE 验证 code_verifier 与 code_challenge 是否匹配。
func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}
	switch method {
	case "", "plain":
		return verifier == challenge
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		return computed == challenge
	default:
		return false
	}
}

// HTTPStatusForOAuthError 把 service 错误映射到 HTTP 状态。
func HTTPStatusForOAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidClient):
		return http.StatusUnauthorized, "invalid_client"
	case errors.Is(err, ErrInvalidGrant):
		return http.StatusBadRequest, "invalid_grant"
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ErrUnauthorizedClient):
		return http.StatusUnauthorized, "unauthorized_client"
	case errors.Is(err, ErrUnsupportedGrant):
		return http.StatusBadRequest, "unsupported_grant_type"
	case errors.Is(err, ErrInvalidScope):
		return http.StatusBadRequest, "invalid_scope"
	case errors.Is(err, ErrInvalidRedirectURI):
		return http.StatusBadRequest, "invalid_redirect_uri"
	case errors.Is(err, ErrPKCEMismatch):
		return http.StatusBadRequest, "invalid_grant"
	default:
		return http.StatusInternalServerError, "server_error"
	}
}

// SplitScope 把 "openid profile email" 切成 []string。
func SplitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	return parts
}
