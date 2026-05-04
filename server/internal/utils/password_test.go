package utils

import (
	"strings"
	"testing"
)

func TestHashAndCheckPassword(t *testing.T) {
	pw := "MySecret!1234"
	h, err := HashPassword(pw, 4) // 测试用低 cost 提速
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if h == pw {
		t.Fatal("hash equals plaintext")
	}
	if !CheckPassword(pw, h) {
		t.Error("correct password should match")
	}
	if CheckPassword("wrong", h) {
		t.Error("wrong password should not match")
	}
	// bcrypt 哈希总以 $2 开头
	if !strings.HasPrefix(h, "$2") {
		t.Errorf("bcrypt hash should start with $2, got %s", h[:5])
	}
}

func TestRandomHex(t *testing.T) {
	a, err := RandomHex(32)
	if err != nil {
		t.Fatalf("RandomHex: %v", err)
	}
	if len(a) != 64 {
		t.Errorf("32 bytes hex should be 64 chars, got %d", len(a))
	}
	b, _ := RandomHex(32)
	if a == b {
		t.Error("two random hex should differ")
	}
}
