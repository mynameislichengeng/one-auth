package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config 是 oneauth-server 的全部配置。
// Secret 类字段（password、密钥等）必须通过环境变量注入；
// 业务参数（TTL、阈值等）写在 config.yaml。
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Cache     CacheConfig     `mapstructure:"cache"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Password  PasswordConfig  `mapstructure:"password"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Bootstrap BootstrapConfig `mapstructure:"bootstrap"`
	Log       LogConfig       `mapstructure:"log"`
}

type RateLimitConfig struct {
	LoginAccountWindow      time.Duration `mapstructure:"login_account_window"`
	LoginAccountMaxFailures int           `mapstructure:"login_account_max_failures"`
	LoginIPWindow           time.Duration `mapstructure:"login_ip_window"`
	LoginIPMaxFailures      int           `mapstructure:"login_ip_max_failures"`
}

type ServerConfig struct {
	Listen          string        `mapstructure:"listen"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	Name            string        `mapstructure:"name"`
	Username        string        `mapstructure:"username"`
	Password        string        `mapstructure:"password"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&multiStatements=true",
		d.Username, d.Password, d.Host, d.Port, d.Name,
	)
}

type CacheConfig struct {
	Driver string             `mapstructure:"driver"` // "memory" | "redis"
	Memory CacheMemoryConfig  `mapstructure:"memory"`
	Redis  CacheRedisConfig   `mapstructure:"redis"`
}

type CacheMemoryConfig struct {
	DefaultTTL      time.Duration `mapstructure:"default_ttl"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

type CacheRedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type JWTConfig struct {
	Algorithm        string        `mapstructure:"algorithm"`
	PrivateKeyPath   string        `mapstructure:"private_key_path"`
	PublicKeyPath    string        `mapstructure:"public_key_path"`
	Issuer           string        `mapstructure:"issuer"`
	AccessTokenTTL   time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL  time.Duration `mapstructure:"refresh_token_ttl"`
	AuthSessionTTL   time.Duration `mapstructure:"auth_session_ttl"`
}

type PasswordConfig struct {
	MinLength  int `mapstructure:"min_length"`
	BcryptCost int `mapstructure:"bcrypt_cost"`
}

type BootstrapConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	AdminEmail    string `mapstructure:"admin_email"`
	AdminPassword string `mapstructure:"admin_password"`
	AdminNickname string `mapstructure:"admin_nickname"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load 从 yaml + env 加载配置。
// 支持 ${VAR:-default} 语法做环境变量替换。
func Load(configPath string) (*Config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := expandEnv(string(raw))

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(expanded)); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// expandEnv 把 ${VAR} 和 ${VAR:-default} 替换为环境变量值。
// 这是因为 viper 默认不直接支持 ${VAR:-default} 语法。
var envPattern = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}`)

func expandEnv(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := envPattern.FindStringSubmatch(match)
		name := groups[1]
		def := groups[2]
		if val, ok := os.LookupEnv(name); ok && val != "" {
			return val
		}
		return def
	})
}

func validate(c *Config) error {
	if c.Database.Host == "" {
		return fmt.Errorf("database.host is required")
	}
	if c.Database.Password == "" {
		return fmt.Errorf("database.password is required (set DB_PASSWORD env)")
	}
	if c.JWT.PrivateKeyPath == "" {
		return fmt.Errorf("jwt.private_key_path is required")
	}
	if c.Password.BcryptCost < 4 || c.Password.BcryptCost > 31 {
		return fmt.Errorf("password.bcrypt_cost must be between 4 and 31")
	}
	if c.Cache.Driver != "memory" && c.Cache.Driver != "redis" {
		return fmt.Errorf("cache.driver must be 'memory' or 'redis'")
	}
	// Bootstrap admin 启用时强制要求密码（避免生产环境忘记导致没人能登录）
	if c.Bootstrap.Enabled && c.Bootstrap.AdminPassword == "" {
		return fmt.Errorf("bootstrap.enabled=true but BOOTSTRAP_ADMIN_PASSWORD is empty; set the env var or disable bootstrap")
	}
	if c.RateLimit.LoginAccountMaxFailures <= 0 {
		return fmt.Errorf("ratelimit.login_account_max_failures must be > 0")
	}
	if c.RateLimit.LoginIPMaxFailures <= 0 {
		return fmt.Errorf("ratelimit.login_ip_max_failures must be > 0")
	}
	return nil
}
