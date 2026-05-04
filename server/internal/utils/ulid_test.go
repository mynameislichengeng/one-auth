package utils

import (
	"strings"
	"testing"
)

func TestNewULID_Format(t *testing.T) {
	id := NewULID()
	if len(id) != 26 {
		t.Errorf("ULID length expected 26, got %d (%s)", len(id), id)
	}
}

func TestNewULID_Unique(t *testing.T) {
	ids := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := NewULID()
		if _, exists := ids[id]; exists {
			t.Fatalf("duplicate ULID: %s", id)
		}
		ids[id] = struct{}{}
	}
}

func TestNewPrefixedULID(t *testing.T) {
	id := NewPrefixedULID("oac")
	if !strings.HasPrefix(id, "oac_") {
		t.Errorf("expected prefix oac_, got %s", id)
	}
	if len(id) != 4+26 {
		t.Errorf("prefixed ULID length expected 30, got %d", len(id))
	}
}
