package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var base64RawURL = base64.RawURLEncoding

// JWTSigner 负责 JWT 的签发与验证。
// 内部缓存 private/public key 对，避免每次签发都读文件。
type JWTSigner struct {
	priv      *rsa.PrivateKey
	pub       *rsa.PublicKey
	issuer    string
	algorithm string
	keyID     string // 公钥的 kid（默认 "default"，未来轮换密钥时区分）
}

// NewJWTSigner 加载已有密钥；如果不存在则自动生成 RSA 2048。
// 这让 dev 环境零配置启动。
func NewJWTSigner(privPath, pubPath, issuer, algorithm string) (*JWTSigner, error) {
	priv, pub, err := loadOrGenerateKeys(privPath, pubPath)
	if err != nil {
		return nil, err
	}
	return &JWTSigner{
		priv:      priv,
		pub:       pub,
		issuer:    issuer,
		algorithm: algorithm,
		keyID:     "default",
	}, nil
}

// KeyID 返回当前签名密钥的 kid。
func (s *JWTSigner) KeyID() string { return s.keyID }

// Issuer 返回 OIDC issuer 标识。
func (s *JWTSigner) Issuer() string { return s.issuer }

// Algorithm 返回签名算法。
func (s *JWTSigner) Algorithm() string { return s.algorithm }

// Claims 是 oneauth access_token 的 JWT payload 结构。
type Claims struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   uint64   `json:"sid,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	TokenUse    string   `json:"token_use,omitempty"` // "access" | "id"
	jwt.RegisteredClaims
}

// IDTokenClaims OIDC id_token payload（详见 OpenID Connect Core §2）。
type IDTokenClaims struct {
	Nonce         string `json:"nonce,omitempty"`
	AuthTime      int64  `json:"auth_time,omitempty"`
	Name          string `json:"name,omitempty"`
	Nickname      string `json:"nickname,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	TokenUse      string `json:"token_use,omitempty"` // "id"
	jwt.RegisteredClaims
}

// IDTokenInput 颁发 id_token 时的入参。
type IDTokenInput struct {
	Subject       string    // user public_id
	Audience      string    // client_id
	Nonce         string    // 来自 authorize 请求的 nonce
	AuthTime      time.Time // 用户实际完成密码验证的时间
	Name          string
	Nickname      string
	Picture       string
	Email         string
	EmailVerified bool
	TTL           time.Duration
	IncludeProfile bool // scope 含 "profile"
	IncludeEmail   bool // scope 含 "email"
}

// SignAccessToken 颁发 access_token。
// sub 应该传 user.public_id (ULID 字符串)。
func (s *JWTSigner) SignAccessToken(sub, tenantID, clientID string, sessionID uint64,
	permissions []string, ttl time.Duration) (token string, jti string, err error) {
	return s.SignAccessTokenWithScope(sub, tenantID, clientID, sessionID, permissions, "", ttl)
}

// SignAccessTokenWithScope 颁发 access_token，带 scope 字段。
func (s *JWTSigner) SignAccessTokenWithScope(sub, tenantID, clientID string, sessionID uint64,
	permissions []string, scope string, ttl time.Duration) (token string, jti string, err error) {

	jti = NewULID()
	now := time.Now()
	claims := &Claims{
		TenantID:    tenantID,
		ClientID:    clientID,
		SessionID:   sessionID,
		Permissions: permissions,
		Scope:       scope,
		TokenUse:    "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   sub,
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	t := jwt.NewWithClaims(s.signingMethod(), claims)
	t.Header["kid"] = s.keyID
	token, err = t.SignedString(s.priv)
	return token, jti, err
}

// SignIDToken 颁发 OIDC id_token。
// scope 含 openid 时调用本函数，含 profile / email 决定哪些 claim 进。
func (s *JWTSigner) SignIDToken(in IDTokenInput) (string, error) {
	now := time.Now()
	claims := &IDTokenClaims{
		Nonce:    in.Nonce,
		AuthTime: in.AuthTime.Unix(),
		TokenUse: "id",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   in.Subject,
			Audience:  []string{in.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(in.TTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        NewULID(),
		},
	}
	if in.IncludeProfile {
		claims.Name = in.Name
		claims.Nickname = in.Nickname
		claims.Picture = in.Picture
	}
	if in.IncludeEmail {
		claims.Email = in.Email
		claims.EmailVerified = in.EmailVerified
	}

	t := jwt.NewWithClaims(s.signingMethod(), claims)
	t.Header["kid"] = s.keyID
	return t.SignedString(s.priv)
}

// JWKS 返回当前公钥的 JWKS（JSON Web Key Set）格式。
// 用于 /.well-known/jwks.json 端点。
func (s *JWTSigner) JWKS() map[string]any {
	n := s.pub.N
	e := s.pub.E

	// e 通常是 65537，转 base64url 后是 "AQAB"
	eBytes := bigIntToBytes(int64(e))

	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": s.keyID,
				"use": "sig",
				"alg": s.algorithm,
				"n":   base64URLEncode(n.Bytes()),
				"e":   base64URLEncode(eBytes),
			},
		},
	}
}

// bigIntToBytes 把 int64（如 RSA exponent）转成最少字节的 big-endian。
func bigIntToBytes(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var buf []byte
	for v > 0 {
		buf = append([]byte{byte(v & 0xff)}, buf...)
		v >>= 8
	}
	return buf
}

func base64URLEncode(data []byte) string {
	// 用 raw url encoding（无 padding）—— RFC 7515 要求
	return base64RawURL.EncodeToString(data)
}

// Verify 验证签名并返回 claims。
// 不检查黑名单（黑名单由 middleware 单独负责）。
func (s *JWTSigner) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	t, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		// 严格匹配预期算法，防止算法替换攻击。
		if t.Method.Alg() != s.algorithm {
			return nil, fmt.Errorf("unexpected signing alg: %s", t.Method.Alg())
		}
		return s.pub, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("token invalid")
	}
	return claims, nil
}

// PublicKey 暴露公钥（给 JWKS 端点用）。
func (s *JWTSigner) PublicKey() *rsa.PublicKey {
	return s.pub
}

func (s *JWTSigner) signingMethod() jwt.SigningMethod {
	switch s.algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	default:
		return jwt.SigningMethodRS256
	}
}

// HashRefreshToken 把 refresh_token 原文哈希为 hex。
// 数据库只存哈希，不存原文。
func HashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// loadOrGenerateKeys 加载或自动生成 RSA 密钥对。
func loadOrGenerateKeys(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if _, err := os.Stat(privPath); errors.Is(err, os.ErrNotExist) {
		// 自动生成
		if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
			return nil, nil, fmt.Errorf("mkdir keys: %w", err)
		}

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("generate rsa key: %w", err)
		}

		// 写私钥
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
			return nil, nil, fmt.Errorf("write private key: %w", err)
		}

		// 写公钥
		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
			return nil, nil, fmt.Errorf("write public key: %w", err)
		}

		return priv, &priv.PublicKey, nil
	}

	// 加载已有
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, nil, errors.New("invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("private key is not RSA")
	}
	return priv, &priv.PublicKey, nil
}
