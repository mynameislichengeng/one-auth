package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJWTSigner_SignAndVerify(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "priv.pem")
	pub := filepath.Join(dir, "pub.pem")

	signer, err := NewJWTSigner(priv, pub, "oneauth-test", "RS256")
	if err != nil {
		t.Fatalf("NewJWTSigner: %v", err)
	}

	// 文件应该被自动生成
	if _, err := os.Stat(priv); err != nil {
		t.Fatalf("private key not created: %v", err)
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("public key not created: %v", err)
	}

	tok, jti, err := signer.SignAccessToken("01HKQXSUB", "main", "admin_web", "01HKQXSESSION0FAMILY00ULID",
		[]string{"user:read"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	if jti == "" {
		t.Fatal("empty jti")
	}

	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "01HKQXSUB" {
		t.Errorf("Subject mismatch: %s", claims.Subject)
	}
	if claims.TenantID != "main" {
		t.Errorf("TenantID mismatch: %s", claims.TenantID)
	}
	if claims.SessionID != "01HKQXSESSION0FAMILY00ULID" {
		t.Errorf("SessionID mismatch: %s", claims.SessionID)
	}
	if claims.ID != jti {
		t.Errorf("jti mismatch: %s vs %s", claims.ID, jti)
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "user:read" {
		t.Errorf("Permissions mismatch: %v", claims.Permissions)
	}
}

func TestJWTSigner_VerifyTamperedTokenFails(t *testing.T) {
	dir := t.TempDir()
	signer, err := NewJWTSigner(
		filepath.Join(dir, "priv.pem"),
		filepath.Join(dir, "pub.pem"),
		"oneauth-test", "RS256")
	if err != nil {
		t.Fatalf("NewJWTSigner: %v", err)
	}

	tok, _, err := signer.SignAccessToken("sub1", "main", "client", "fam-1", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 篡改 payload（中段）：必然导致签名不匹配
	dot1 := strings.Index(tok, ".")
	dot2 := strings.Index(tok[dot1+1:], ".") + dot1 + 1
	// 在 payload 中间替换一个字符
	mid := dot1 + (dot2-dot1)/2
	var b byte = 'A'
	if tok[mid] == 'A' {
		b = 'B'
	}
	tampered := tok[:mid] + string(b) + tok[mid+1:]
	if _, err := signer.Verify(tampered); err == nil {
		t.Fatal("tampered token should fail verification")
	}
}

func TestJWTSigner_VerifyExpiredFails(t *testing.T) {
	dir := t.TempDir()
	signer, _ := NewJWTSigner(
		filepath.Join(dir, "priv.pem"),
		filepath.Join(dir, "pub.pem"),
		"oneauth-test", "RS256")

	tok, _, _ := signer.SignAccessToken("sub", "main", "c", "fam-1", nil, -time.Hour)

	if _, err := signer.Verify(tok); err == nil {
		t.Fatal("expired token should fail verification")
	}
}

func TestHashRefreshToken_Stable(t *testing.T) {
	a := HashRefreshToken("token-1")
	b := HashRefreshToken("token-1")
	if a != b {
		t.Errorf("hash should be deterministic")
	}
	c := HashRefreshToken("token-2")
	if a == c {
		t.Errorf("different inputs should produce different hashes")
	}
	if len(a) != 64 {
		t.Errorf("hash hex length should be 64, got %d", len(a))
	}
}
