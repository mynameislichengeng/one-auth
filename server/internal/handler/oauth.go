package handler

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/licheng/oneauth/server/internal/service"
	"github.com/licheng/oneauth/server/internal/utils"
)

// CookieName 是 oneauth 自身 SSO cookie 的名字。详见 02 文档 §IV.1。
const CookieName = "oneauth_sid"

// OAuthHandler 实现 /oauth/* 端点 + 登录页。
type OAuthHandler struct {
	svc          *service.OAuthService
	authSvc      *service.AuthService
	blocklist    service.BlocklistChecker // for introspect/revoke
	blocklistAdd service.BlocklistAdder
	loginTmpl    *template.Template
	cookieSecure bool
	publicBaseURL string // for OIDC discovery, e.g., http://localhost:8080
}

// HandlerConfig 统一传入 OAuthHandler 的依赖。
type HandlerConfig struct {
	Service       *service.OAuthService
	AuthService   *service.AuthService
	Blocklist     service.BlocklistChecker
	BlocklistAdd  service.BlocklistAdder
	CookieSecure  bool
	PublicBaseURL string
}

func NewOAuthHandler(cfg HandlerConfig) *OAuthHandler {
	return &OAuthHandler{
		svc:           cfg.Service,
		authSvc:       cfg.AuthService,
		blocklist:     cfg.Blocklist,
		blocklistAdd:  cfg.BlocklistAdd,
		loginTmpl:     template.Must(template.New("login").Parse(loginHTML)),
		cookieSecure:  cfg.CookieSecure,
		publicBaseURL: cfg.PublicBaseURL,
	}
}

// GET /oauth/authorize
//
// 处理浏览器发起的授权请求（OAuth Authorization Code + PKCE）。
//
// 流程：
//  1. 校验 client_id / redirect_uri / response_type
//  2. 检查 oneauth_sid cookie：
//     - 有效 → 直接颁码 + 跳转 redirect_uri
//     - 无效 → 渲染登录页（含 return_to 隐藏字段保留 authorize 上下文）
func (h *OAuthHandler) Authorize(c *gin.Context) {
	// OAuth 协议合规：授权响应不允许中间代理缓存
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	scope := c.Query("scope")
	nonce := c.Query("nonce")
	responseType := c.Query("response_type")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" {
		utils.BadRequest(c, "missing client_id or redirect_uri")
		return
	}
	if responseType != "code" {
		utils.BadRequest(c, "response_type must be 'code'")
		return
	}

	client, err := h.svc.LookupClient(c.Request.Context(), clientID)
	if err != nil {
		// 在 client 都还没认出来之前，绝不重定向（防开放重定向）
		utils.Unauthorized(c, "invalid client")
		return
	}
	if !client.AllowsRedirectURI(redirectURI) {
		// 同样不重定向
		utils.BadRequest(c, "invalid redirect_uri")
		return
	}
	if client.RequirePKCE && codeChallenge == "" {
		h.redirectAuthError(c, redirectURI, state, "invalid_request",
			"code_challenge required (PKCE)")
		return
	}

	// 拿 cookie，看是否已登录
	sid, _ := c.Cookie(CookieName)
	user, authTime, err := h.svc.VerifyAuthSession(c.Request.Context(), sid)
	if err != nil {
		// 未登录 → 渲染登录页，保留 authorize 上下文
		h.renderLoginPage(c, http.StatusOK, "", c.Request.URL.RawQuery)
		return
	}

	// 已登录 → 颁码
	result, err := h.svc.IssueCode(c.Request.Context(), service.AuthorizeRequest{
		Client:              client,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		AuthTime:            authTime,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ResponseType:        responseType,
	}, user)
	if err != nil {
		h.redirectAuthError(c, redirectURI, state, mapAuthorizeError(err), err.Error())
		return
	}

	h.redirectAuthSuccess(c, result.RedirectURI, result.Code, result.State)
}

// GET /login —— 直接打开登录页（用户也能从这里手动登录）。
func (h *OAuthHandler) GetLogin(c *gin.Context) {
	rawQuery := safeReturnTo(c.Query("return_to"))
	h.renderLoginPage(c, http.StatusOK, "", rawQuery)
}

// POST /login —— 处理登录页表单提交（form-urlencoded）。
//
// 成功：种 oneauth_sid cookie，重定向回 return_to（如果有）或 /
// 失败：重新渲染登录页，显示错误。
func (h *OAuthHandler) PostLogin(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	returnTo := safeReturnTo(c.PostForm("return_to")) // 防开放重定向

	user, err := h.svc.AuthenticatePassword(c.Request.Context(), email, password,
		c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		errMsg := "邮箱或密码错误"
		if errors.Is(err, service.ErrUserNotActive) {
			errMsg = "账号已被冻结"
		}
		h.renderLoginPage(c, http.StatusUnauthorized, errMsg, returnTo)
		return
	}

	// 创建 SSO session + 种 cookie
	sid, err := h.svc.CreateAuthSession(c.Request.Context(), user, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		utils.Internal(c, err)
		return
	}
	h.setSessionCookie(c, sid)

	// 跳回 authorize（如果是从 /authorize 跳过来登录的）
	if returnTo != "" {
		c.Redirect(http.StatusFound, "/oauth/authorize?"+returnTo)
		return
	}
	c.Redirect(http.StatusFound, "/")
}

// GET /logout —— 撤销 cookie session + 清 cookie。
func (h *OAuthHandler) Logout(c *gin.Context) {
	sid, _ := c.Cookie(CookieName)
	if sid != "" {
		_ = h.svc.RevokeAuthSession(c.Request.Context(), sid)
	}
	h.clearSessionCookie(c)
	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

// POST /oauth/token
//
// 支持 grant_type:
//   - authorization_code (含 PKCE code_verifier)
//   - refresh_token
func (h *OAuthHandler) Token(c *gin.Context) {
	// OAuth RFC 6749 §5.1：token 响应禁止任何缓存
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	grantType := c.PostForm("grant_type")
	if grantType == "" {
		utils.BadRequest(c, "grant_type required")
		return
	}

	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	// 也支持 HTTP Basic Auth
	if clientID == "" {
		if u, p, ok := c.Request.BasicAuth(); ok {
			clientID = u
			clientSecret = p
		}
	}
	if clientID == "" {
		utils.BadRequest(c, "client_id required")
		return
	}

	pair, err := h.svc.ExchangeToken(c.Request.Context(), service.TokenExchangeRequest{
		GrantType:    grantType,
		Code:         c.PostForm("code"),
		RedirectURI:  c.PostForm("redirect_uri"),
		CodeVerifier: c.PostForm("code_verifier"),
		RefreshToken: c.PostForm("refresh_token"),
		Scope:        c.PostForm("scope"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		IP:           c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		status, code := service.HTTPStatusForOAuthError(err)
		c.JSON(status, gin.H{
			"error":             code,
			"error_description": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, pair)
}

// GET /oauth/userinfo —— OIDC 用户信息端点。需要 Bearer access_token。
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		utils.Unauthorized(c, "Bearer token required")
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	claims, err := h.authSvc.VerifyAccessToken(c.Request.Context(), token)
	if err != nil {
		utils.Unauthorized(c, "invalid or revoked token")
		return
	}
	resp, err := h.svc.BuildUserInfo(c.Request.Context(), claims)
	if err != nil {
		utils.Internal(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// GET /.well-known/openid-configuration —— OIDC discovery。
func (h *OAuthHandler) Discovery(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300") // 5 min 公共缓存
	base := h.publicBaseURL
	if base == "" {
		base = "http://" + c.Request.Host
	}
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"introspection_endpoint":                base + "/oauth/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"claims_supported":                      []string{"sub", "name", "nickname", "picture", "email", "email_verified", "tenant_id", "auth_time", "nonce"},
	})
}

// GET /.well-known/jwks.json —— 公钥发布。业务方拿这里的公钥本地验签 JWT。
func (h *OAuthHandler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600") // 1 小时公共缓存
	c.JSON(http.StatusOK, h.svc.JWKS())
}

// POST /oauth/revoke —— RFC 7009 token 撤销。
func (h *OAuthHandler) Revoke(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	clientID, clientSecret, ok := readClientCreds(c)
	if !ok || clientID == "" {
		utils.BadRequest(c, "client_id required")
		return
	}
	client, err := h.svc.LookupClient(c.Request.Context(), clientID)
	if err != nil {
		utils.Unauthorized(c, "invalid client")
		return
	}
	if err := h.svc.VerifyClientSecret(client, clientSecret); err != nil {
		utils.Unauthorized(c, "invalid client")
		return
	}

	token := c.PostForm("token")
	hint := c.PostForm("token_type_hint") // "access_token" | "refresh_token"
	if token == "" {
		// RFC 7009 §2.2: 即使 token 字段缺失也可以返 200 但提示
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	switch hint {
	case "refresh_token":
		_ = h.svc.RevokeRefreshToken(c.Request.Context(), token)
	case "access_token":
		if h.blocklistAdd != nil {
			_ = h.svc.RevokeAccessToken(c.Request.Context(), token, h.blocklistAdd)
		}
	default:
		// 不知道类型时两个都试一下
		if h.blocklistAdd != nil {
			_ = h.svc.RevokeAccessToken(c.Request.Context(), token, h.blocklistAdd)
		}
		_ = h.svc.RevokeRefreshToken(c.Request.Context(), token)
	}
	// RFC 7009 §2.2: 一律返回 200（避免暴露 token 状态给攻击者）
	c.JSON(http.StatusOK, gin.H{})
}

// POST /oauth/introspect —— RFC 7662 token 内省。
func (h *OAuthHandler) Introspect(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	clientID, clientSecret, ok := readClientCreds(c)
	if !ok || clientID == "" {
		utils.BadRequest(c, "client_id required")
		return
	}
	client, err := h.svc.LookupClient(c.Request.Context(), clientID)
	if err != nil {
		utils.Unauthorized(c, "invalid client")
		return
	}
	if err := h.svc.VerifyClientSecret(client, clientSecret); err != nil {
		utils.Unauthorized(c, "invalid client")
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	res, err := h.svc.IntrospectToken(c.Request.Context(), token, h.blocklist)
	if err != nil {
		utils.Internal(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// readClientCreds 从 Basic Auth 或 form 读出 client_id/secret。
func readClientCreds(c *gin.Context) (string, string, bool) {
	if u, p, ok := c.Request.BasicAuth(); ok && u != "" {
		return u, p, true
	}
	return c.PostForm("client_id"), c.PostForm("client_secret"), true
}

// ----- helpers -----

func (h *OAuthHandler) renderLoginPage(c *gin.Context, status int, errMsg, returnTo string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	if err := h.loginTmpl.Execute(c.Writer, map[string]any{
		"Error":    errMsg,
		"ReturnTo": returnTo,
	}); err != nil {
		// status 已经写出，body 写一半失败：只能记日志
		slog.Error("render login template failed", "err", err, "path", c.Request.URL.Path)
	}
}

func (h *OAuthHandler) redirectAuthSuccess(c *gin.Context, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		utils.BadRequest(c, "invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func (h *OAuthHandler) redirectAuthError(c *gin.Context, redirectURI, state, errCode, errDesc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		utils.BadRequest(c, errDesc)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func (h *OAuthHandler) setSessionCookie(c *gin.Context, sid string) {
	// 注意：dev 环境用 HTTP，Secure 必须 false 浏览器才接受
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)
}

func (h *OAuthHandler) clearSessionCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)
}

func mapAuthorizeError(err error) string {
	switch {
	case errors.Is(err, service.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, service.ErrInvalidRedirectURI):
		return "invalid_request"
	case errors.Is(err, service.ErrUnauthorizedClient):
		return "unauthorized_client"
	default:
		return "server_error"
	}
}

// 简化的登录页（生产可换成 SPA）。
const loginHTML = `<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>oneauth · 登录</title>
  <style>
    body { font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
           background: #f6f7f9; color: #222; margin: 0; }
    main { max-width: 360px; margin: 80px auto; padding: 28px;
           background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    h1 { font-size: 22px; margin: 0 0 4px; }
    p.sub { color: #666; margin-top: 0; font-size: 13px; }
    label { display: block; font-size: 13px; color: #444; margin-top: 16px; }
    input[type=email], input[type=password] {
      width: 100%; box-sizing: border-box; padding: 9px 10px;
      border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px;
    }
    button { margin-top: 22px; width: 100%; padding: 10px;
             background: #2c63e6; color: #fff; border: 0; border-radius: 6px;
             font-size: 14px; cursor: pointer; }
    button:hover { background: #2554c8; }
    .err { margin-top: 14px; padding: 10px 12px; background: #fff1f0;
           color: #b00020; border: 1px solid #ffd6d3; border-radius: 6px;
           font-size: 13px; }
    .footer { margin-top: 14px; font-size: 12px; color: #888; text-align: center; }
  </style>
</head>
<body>
  <main>
    <h1>oneauth</h1>
    <p class="sub">登录到统一身份服务</p>
    {{ if .Error }}<div class="err">{{ .Error }}</div>{{ end }}
    <form method="post" action="/login">
      <label>邮箱<input type="email" name="email" required autofocus></label>
      <label>密码<input type="password" name="password" required></label>
      <input type="hidden" name="return_to" value="{{ .ReturnTo }}">
      <button type="submit">登录</button>
    </form>
    <p class="footer">v0.2 · oneauth</p>
  </main>
</body>
</html>`

// safeReturnTo 防止 return_to 被构造为开放重定向攻击向量。
// 我们允许的 return_to 是 /oauth/authorize 的 query string（如 "client_id=x&...")。
// 拒绝：包含 // 或 http(s):// 前缀（防止被解析为 absolute URL）、含换行（防 header 注入）。
func safeReturnTo(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return ""
	}
	if strings.ContainsAny(raw, "\r\n") {
		return ""
	}
	return raw
}
