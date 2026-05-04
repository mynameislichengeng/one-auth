package config

import (
	"os"
	"testing"
)

func TestExpandEnv(t *testing.T) {
	t.Setenv("FOO", "hello")
	t.Setenv("EMPTY_VAR", "")

	cases := []struct {
		in, want string
	}{
		{"${FOO}", "hello"},
		{"${MISSING:-default}", "default"},
		{"${FOO:-default}", "hello"},
		{"${MISSING}", ""},
		{"${EMPTY_VAR:-fallback}", "fallback"}, // 空字符串视同未设置
		{"prefix-${FOO}-suffix", "prefix-hello-suffix"},
		{"no-vars-here", "no-vars-here"},
	}
	for _, c := range cases {
		got := expandEnv(c.in)
		if got != c.want {
			t.Errorf("expandEnv(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoad_Validates(t *testing.T) {
	tmp, err := os.CreateTemp("", "cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	// 缺 DB password
	tmp.WriteString(`
server:
  listen: ":8080"
database:
  host: localhost
  port: 3306
  name: x
  username: y
  password: ${DB_PASSWORD}
cache:
  driver: memory
jwt:
  algorithm: RS256
  private_key_path: /tmp/p
  public_key_path: /tmp/pub
  issuer: x
password:
  min_length: 8
  bcrypt_cost: 12
ratelimit:
  login_account_window: 15m
  login_account_max_failures: 5
  login_ip_window: 1h
  login_ip_max_failures: 100
bootstrap:
  enabled: false
log:
  level: info
  format: text
`)
	tmp.Close()

	t.Setenv("DB_PASSWORD", "")
	if _, err := Load(tmp.Name()); err == nil {
		t.Error("expected validation error for missing DB_PASSWORD")
	}

	t.Setenv("DB_PASSWORD", "secret")
	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Password != "secret" {
		t.Errorf("DB_PASSWORD env not applied: %q", cfg.Database.Password)
	}
}
