package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// JSONStrings 是 ["a","b"] 这种 JSON 数组与 Go []string 的转换器。
type JSONStrings []string

func (j *JSONStrings) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	var b []byte
	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return errors.New("unsupported type for JSONStrings")
	}
	if len(b) == 0 {
		*j = nil
		return nil
	}
	return json.Unmarshal(b, j)
}

func (j JSONStrings) Value() (driver.Value, error) {
	if j == nil {
		return "[]", nil
	}
	return json.Marshal(j)
}

// OAuthClient 接入方应用配置。
type OAuthClient struct {
	ID                       uint64      `gorm:"column:id;primaryKey;autoIncrement"`
	PublicID                 string      `gorm:"column:public_id;type:char(26);uniqueIndex:uk_public_id"`
	ClientID                 string      `gorm:"column:client_id;type:varchar(64);uniqueIndex:uk_client_id"`
	ClientSecretHash         string      `gorm:"column:client_secret_hash;type:varchar(255)"`
	Name                     string      `gorm:"column:name;type:varchar(200)"`
	Description              string      `gorm:"column:description;type:varchar(500)"`
	ClientType               string      `gorm:"column:client_type;type:varchar(32)"`
	RedirectURIs             JSONStrings `gorm:"column:redirect_uris;type:json"`
	GrantTypes               JSONStrings `gorm:"column:grant_types;type:json"`
	AllowedScopes            JSONStrings `gorm:"column:allowed_scopes;type:json"`
	AllowedTenantTypes       JSONStrings `gorm:"column:allowed_tenant_types;type:json"`
	RequirePKCE              bool        `gorm:"column:require_pkce;default:true"`
	AccessTokenTTLSeconds    uint32      `gorm:"column:access_token_ttl_seconds;default:7200"`
	RefreshTokenTTLSeconds   uint32      `gorm:"column:refresh_token_ttl_seconds;default:2592000"`
	AllowedIPCIDRs           JSONStrings `gorm:"column:allowed_ip_cidrs;type:json"`
	Status                   string      `gorm:"column:status;type:varchar(20);default:active"`
	CreatedAt                time.Time   `gorm:"column:created_at"`
	UpdatedAt                time.Time   `gorm:"column:updated_at"`
	CreatedBy                *uint64     `gorm:"column:created_by"`
	UpdatedBy                *uint64     `gorm:"column:updated_by"`
	Deleted                  bool        `gorm:"column:deleted;default:false"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

// ClientType 常量。
const (
	ClientTypeFirstPartyConfidential = "first_party_confidential"
	ClientTypeFirstPartyPublic       = "first_party_public"
	ClientTypeThirdParty             = "third_party"
	ClientTypeService                = "service"
)

// GrantType 常量。
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeClientCredentials = "client_credentials"
)

// AllowsRedirectURI 严格匹配检查（OAuth 安全要求，不允许模糊匹配）。
func (c *OAuthClient) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// AllowsGrantType 校验 grant_type 是否在该 client 允许列表里。
func (c *OAuthClient) AllowsGrantType(gt string) bool {
	for _, allowed := range c.GrantTypes {
		if allowed == gt {
			return true
		}
	}
	return false
}

// IsConfidential 是否需要 client_secret 验证。
func (c *OAuthClient) IsConfidential() bool {
	return c.ClientType == ClientTypeFirstPartyConfidential ||
		c.ClientType == ClientTypeThirdParty ||
		c.ClientType == ClientTypeService
}

// IsFirstParty 自家应用（跳过用户授权确认页）。
func (c *OAuthClient) IsFirstParty() bool {
	return c.ClientType == ClientTypeFirstPartyConfidential ||
		c.ClientType == ClientTypeFirstPartyPublic
}
