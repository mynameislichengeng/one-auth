package utils

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID 生成器（并发安全）。
// 同一毫秒内生成多个 ULID 时会单调递增。
var (
	ulidEntropy *ulid.MonotonicEntropy
	ulidMu      sync.Mutex
)

func init() {
	ulidEntropy = ulid.Monotonic(rand.Reader, 0)
}

// NewULID 生成一个 26 字符的 ULID 字符串。
func NewULID() string {
	ulidMu.Lock()
	defer ulidMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(time.Now()), ulidEntropy).String()
}

// NewPrefixedULID 生成带前缀的 ULID，如 "oac_01HKQX..."
func NewPrefixedULID(prefix string) string {
	return prefix + "_" + NewULID()
}
