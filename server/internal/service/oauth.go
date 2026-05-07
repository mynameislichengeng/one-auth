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
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	IssuedAt            time.Time `json:"issued_at"`
	AuthTime            time.Time `json:"auth_time"` // 用户密码验证完成时间
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
	Nonce               string // OIDC：防 id_token 重放
	AuthTime            time.Time
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

	// scope 必须是 client.AllowedScopes 的子集（OAuth 2.0 §3.3 + 防越权）
	// 与 client_credentials 的过滤逻辑保持一致。
	requestedScopes := SplitScope(req.Scope)
	for _, sc := range requestedScopes {
		if !contains(req.Client.AllowedScopes, sc) {
			return nil, ErrInvalidScope
		}
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

	authTime := req.AuthTime
	if authTime.IsZero() {
		authTime = time.Now()
	}

	data := AuthCodeData{
		ClientID:            req.Client.ClientID,
		UserID:              user.ID,
		UserPublicID:        user.PublicID,
		TenantID:            mainTenant.ID,
		TenantCode:          mainTenant.Code,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		IssuedAt:            time.Now(),
		AuthTime:            authTime,
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
	case model.GrantTypeClientCredentials:
		return s.IssueClientCredentialsToken(ctx, client, req.Scope)
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

	// 拿用户的 email 给 id_token 用（如果 scope 含 email）
	email, emailVerified := s.lookupUserEmail(ctx, user.ID)

	return s.issueTokensForClient(ctx, issueTokensInput{
		User:          user,
		Tenant:        tenant,
		Client:        client,
		IP:            req.IP,
		UserAgent:     req.UserAgent,
		Scope:         data.Scope,
		Nonce:         data.Nonce,
		AuthTime:      data.AuthTime,
		Email:         email,
		EmailVerified: emailVerified,
	})
}

// lookupUserEmail 找用户的 primary email 凭证（用于 id_token email claim）。
// 没有则返回空。verified_at 不为 NULL 视为已验证。
func (s *OAuthService) lookupUserEmail(ctx context.Context, userID uint64) (string, bool) {
	var ua model.UserAuth
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND auth_type = ?", userID, model.AuthTypeEmail).
		Order("id ASC").
		First(&ua).Error
	if err != nil {
		return "", false
	}
	return ua.Identifier, ua.VerifiedAt != nil
}

// nolint:unused — exchangeRefreshToken 在 ExchangeToken 里通过 switch 分发调用
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
			user.PublicID, tenant.Code, client.ClientID, newSession.FamilyID,
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

type issueTokensInput struct {
	User          *model.User
	Tenant        *model.Tenant
	Client        *model.OAuthClient
	IP            string
	UserAgent     string
	Scope         string
	Nonce         string    // OIDC nonce（仅 authorization_code 流）
	AuthTime      time.Time // 用户密码验证完成时间
	Email         string
	EmailVerified bool
}

func (s *OAuthService) issueTokensForClient(ctx context.Context, in issueTokensInput) (*TokenPair, error) {
	now := time.Now()
	refreshRaw, err := utils.RandomHex(32)
	if err != nil {
		return nil, err
	}
	familyID := utils.NewULID()
	session := &model.UserSession{
		UserID:           in.User.ID,
		TenantID:         in.Tenant.ID,
		ClientID:         in.Client.ClientID,
		RefreshTokenHash: utils.HashRefreshToken(refreshRaw),
		FamilyID:         familyID,
		UserAgent:        in.UserAgent,
		IP:               in.IP,
		IssuedAt:         now,
		ExpiresAt:        now.Add(time.Duration(in.Client.RefreshTokenTTLSeconds) * time.Second),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	ttl := time.Duration(in.Client.AccessTokenTTLSeconds) * time.Second
	access, _, err := s.signer.SignAccessTokenWithScope(
		in.User.PublicID, in.Tenant.Code, in.Client.ClientID, session.FamilyID,
		[]string{}, in.Scope, ttl,
	)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	pair := &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresIn:        int64(ttl.Seconds()),
		RefreshToken:     refreshRaw,
		RefreshExpiresAt: session.ExpiresAt,
		Scope:            in.Scope,
		UserPublicID:     in.User.PublicID,
		TenantCode:       in.Tenant.Code,
		Nickname:         in.User.Nickname,
	}

	// scope 含 openid → 颁发 id_token（OIDC）
	scopes := SplitScope(in.Scope)
	if hasScope(scopes, "openid") {
		authTime := in.AuthTime
		if authTime.IsZero() {
			authTime = now
		}
		idToken, err := s.signer.SignIDToken(utils.IDTokenInput{
			Subject:        in.User.PublicID,
			Audience:       in.Client.ClientID,
			Nonce:          in.Nonce,
			AuthTime:       authTime,
			Name:           in.User.Nickname,
			Nickname:       in.User.Nickname,
			Picture:        in.User.AvatarURL,
			Email:          in.Email,
			EmailVerified:  in.EmailVerified,
			TTL:            ttl,
			IncludeProfile: hasScope(scopes, "profile"),
			IncludeEmail:   hasScope(scopes, "email"),
		})
		if err != nil {
			return nil, fmt.Errorf("sign id_token: %w", err)
		}
		pair.IDToken = idToken
	}

	return pair, nil
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
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

// VerifyAuthSession 取出 cookie 对应的 user 与 session 元数据（验证 session 有效）。
// 返回的 authTime 是用户最近一次完成密码验证的时间（OIDC id_token 的 auth_time claim）。
func (s *OAuthService) VerifyAuthSession(ctx context.Context, sid string) (*model.User, time.Time, error) {
	if sid == "" {
		return nil, time.Time{}, ErrAuthSessionInvalid
	}
	sess, err := s.authSessions.FindActiveBySessionID(ctx, sid)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, time.Time{}, ErrAuthSessionInvalid
		}
		return nil, time.Time{}, err
	}
	user, err := s.users.FindByID(ctx, sess.UserID)
	if err != nil {
		return nil, time.Time{}, err
	}
	if user.Status != model.UserStatusActive {
		return nil, time.Time{}, ErrAuthSessionInvalid
	}
	_ = s.authSessions.Touch(ctx, sess.ID)
	return user, sess.CreatedAt, nil
}

// RevokeAuthSession 撤销 cookie session（用于登出）。
func (s *OAuthService) RevokeAuthSession(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	return s.authSessions.Revoke(ctx, sid)
}

// UserInfoResponse 是 /oauth/userinfo 的响应（OIDC 标准）。
type UserInfoResponse struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	Nickname      string `json:"nickname,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
}

// BuildUserInfo 给 /oauth/userinfo 用：根据 access_token 的 sub + scope 拼用户信息。
func (s *OAuthService) BuildUserInfo(ctx context.Context, claims *utils.Claims) (*UserInfoResponse, error) {
	user, err := s.users.FindByPublicID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if user.Status != model.UserStatusActive {
		return nil, ErrInvalidGrant
	}

	resp := &UserInfoResponse{
		Sub:       user.PublicID,
		TenantID:  claims.TenantID,
		UpdatedAt: user.UpdatedAt.Unix(),
	}
	scopes := SplitScope(claims.Scope)
	if hasScope(scopes, "profile") {
		resp.Name = user.Nickname
		resp.Nickname = user.Nickname
		resp.Picture = user.AvatarURL
	}
	if hasScope(scopes, "email") {
		email, verified := s.lookupUserEmail(ctx, user.ID)
		resp.Email = email
		resp.EmailVerified = verified
	}
	return resp, nil
}

// IntrospectResult 是 /oauth/introspect 的结果（RFC 7662）。
type IntrospectResult struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	Sub       string `json:"sub,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Aud       string `json:"aud,omitempty"`
	JTI       string `json:"jti,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// IntrospectToken 接收一个 access_token 字符串，返回它是否有效及元数据。
// 不需要解密 refresh_token（hash 不可逆，不在这做）。
func (s *OAuthService) IntrospectToken(ctx context.Context, token string, blocklist BlocklistChecker) (*IntrospectResult, error) {
	claims, err := s.signer.Verify(token)
	if err != nil {
		return &IntrospectResult{Active: false}, nil
	}
	// 黑名单检查
	if blocklist != nil {
		blocked, err := blocklist.IsBlocked(ctx, claims.ID)
		if err != nil {
			return nil, err
		}
		if blocked {
			return &IntrospectResult{Active: false}, nil
		}
	}
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}
	return &IntrospectResult{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Sub:       claims.Subject,
		TokenType: "Bearer",
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Iss:       claims.Issuer,
		Aud:       aud,
		JTI:       claims.ID,
		TenantID:  claims.TenantID,
	}, nil
}

// BlocklistChecker 让 OAuthService 不直接依赖 blocklist repo（避免循环引用）。
type BlocklistChecker interface {
	IsBlocked(ctx context.Context, jti string) (bool, error)
}

// RevokeAccessToken 把 access_token 的 jti 加入黑名单。
//
// 三种 token 形态：
//   - 用户 access_token：claims.Subject = user.public_id → 查 user.id 入黑名单
//   - service token（client_credentials grant）：claims.Subject = client_id，
//     不对应任何用户。我们仍要把 jti 入黑名单（防止泄露的 service token 滥用），
//     此时 user_id 留 0 作为"非用户级"标记
//   - 用户已删除：jti 仍入黑名单（user_id=0），不影响 token 失效
func (s *OAuthService) RevokeAccessToken(ctx context.Context, token string, blocklist BlocklistAdder) error {
	claims, err := s.signer.Verify(token)
	if err != nil {
		// RFC 7009: 无效 token 也返回 200（避免暴露 token 状态）
		return nil
	}
	now := time.Now()
	if claims.ExpiresAt.Time.Before(now) {
		// 已过期，没必要加黑名单
		return nil
	}

	// 用户 token：claims.Subject 是 user public_id；查到映射 user.id
	// service token：claims.Subject 是 client_id，查不到 → 用 0 作为占位
	var userID uint64
	if user, err := s.users.FindByPublicID(ctx, claims.Subject); err == nil {
		userID = user.ID
	}
	return blocklist.Add(ctx, &model.JWTBlocklist{
		JTI:       claims.ID,
		UserID:    userID,
		Reason:    model.BlocklistReasonAdminRevoke,
		RevokedAt: now,
		ExpiresAt: claims.ExpiresAt.Time,
	})
}

// RevokeRefreshToken 撤销 refresh_token（基于 hash 查表）。
func (s *OAuthService) RevokeRefreshToken(ctx context.Context, token string) error {
	hash := utils.HashRefreshToken(token)
	sess, err := s.sessions.FindByRefreshHash(ctx, hash)
	if err != nil {
		// RFC 7009: 无效 token 也返回 200
		return nil
	}
	return s.sessions.RevokeFamily(ctx, sess.FamilyID)
}

// BlocklistAdder 抽象 add 接口（供 RevokeAccessToken 用）。
type BlocklistAdder interface {
	Add(ctx context.Context, e *model.JWTBlocklist) error
}

// IssueClientCredentialsToken 颁发 service token（grant_type=client_credentials）。
// 没有 user 概念：sub = client_id，无 refresh_token，permissions claim 用 scope 限定。
func (s *OAuthService) IssueClientCredentialsToken(ctx context.Context,
	client *model.OAuthClient, requestedScope string,
) (*TokenPair, error) {
	if !client.AllowsGrantType(model.GrantTypeClientCredentials) {
		return nil, ErrUnauthorizedClient
	}
	// service client 必须是 confidential（已经通过 secret 验证）
	if !client.IsConfidential() {
		return nil, ErrUnauthorizedClient
	}

	// scope 过滤：只允许 client.AllowedScopes 子集
	scopes := SplitScope(requestedScope)
	if len(scopes) == 0 {
		// 默认给 client 配的全部 internal.* scope
		scopes = filterInternalScopes(client.AllowedScopes)
	} else {
		// 校验请求的 scope 在 allowed 内
		for _, sc := range scopes {
			if !contains(client.AllowedScopes, sc) {
				return nil, ErrInvalidScope
			}
		}
	}

	ttl := time.Duration(client.AccessTokenTTLSeconds) * time.Second
	// service token 的 sub 是 client_id（不是 user！），无 session 关联，sid 留空
	access, _, err := s.signer.SignAccessTokenWithScope(
		client.ClientID, "", client.ClientID, "",
		scopes, strings.Join(scopes, " "), ttl,
	)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(ttl.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func contains(arr []string, target string) bool {
	for _, v := range arr {
		if v == target {
			return true
		}
	}
	return false
}

func filterInternalScopes(allowed []string) []string {
	var out []string
	for _, s := range allowed {
		if strings.HasPrefix(s, "internal.") {
			out = append(out, s)
		}
	}
	return out
}

// JWKS 暴露给 handler 用。
func (s *OAuthService) JWKS() map[string]any {
	return s.signer.JWKS()
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

// HTTPStatusForOAuthError 把 service 错误映射到 HTTP 状态 + OAuth error code +
// 固定的 error_description 文案。
//
// 不返回 err.Error() 给客户端（避免内部细节泄露——比如 PKCE 比对的具体长度、
// wrap 链中的内部 path 等）。OAuth 2.0 §5.2 允许省略 error_description，但
// 给客户端开发者一个稳定文案便于排错。
func HTTPStatusForOAuthError(err error) (status int, code string, description string) {
	switch {
	case errors.Is(err, ErrInvalidClient):
		return http.StatusUnauthorized, "invalid_client", "client authentication failed"
	case errors.Is(err, ErrInvalidGrant):
		return http.StatusBadRequest, "invalid_grant", "the provided grant is invalid, expired, or revoked"
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request", "request is missing a required parameter or malformed"
	case errors.Is(err, ErrUnauthorizedClient):
		return http.StatusUnauthorized, "unauthorized_client", "client not authorized for this grant type or resource"
	case errors.Is(err, ErrUnsupportedGrant):
		return http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported"
	case errors.Is(err, ErrInvalidScope):
		return http.StatusBadRequest, "invalid_scope", "requested scope is not allowed for this client"
	case errors.Is(err, ErrInvalidRedirectURI):
		return http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri does not match registered URIs"
	case errors.Is(err, ErrPKCEMismatch):
		return http.StatusBadRequest, "invalid_grant", "PKCE code_verifier does not match code_challenge"
	default:
		return http.StatusInternalServerError, "server_error", "internal server error"
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
