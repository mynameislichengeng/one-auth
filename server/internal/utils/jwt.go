package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSigner 负责 JWT 的签发与验证。
// 内部缓存 private/public key 对，避免每次签发都读文件。
type JWTSigner struct {
	priv      *rsa.PrivateKey
	pub       *rsa.PublicKey
	issuer    string
	algorithm string
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
	}, nil
}

// Claims 是 oneauth 的 JWT payload 结构。
type Claims struct {
	TenantID    string   `json:"tenant_id,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   uint64   `json:"sid,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// SignAccessToken 颁发 access_token。
// sub 应该传 user.public_id (ULID 字符串)。
func (s *JWTSigner) SignAccessToken(sub, tenantID, clientID string, sessionID uint64,
	permissions []string, ttl time.Duration) (token string, jti string, err error) {

	jti = NewULID()
	now := time.Now()
	claims := &Claims{
		TenantID:    tenantID,
		ClientID:    clientID,
		SessionID:   sessionID,
		Permissions: permissions,
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
	token, err = t.SignedString(s.priv)
	return token, jti, err
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
