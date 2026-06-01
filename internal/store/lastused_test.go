package store

import (
	"testing"

	"better-gh/internal/policy"
)

// Regression for FINDING O (DoS): LastUsed persistence is debounced, so a flood of allowed
// requests cannot amplify into a tokens.json rewrite per request. A second touch within the
// interval must not change the recorded LastUsed (it skips the rewrite).
func TestLastUsedDebounced(t *testing.T) {
	s, err := Open(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.Create("t", policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	s.TouchLastUsed(tok.ID)
	first := s.Get(tok.ID).LastUsed
	if first.IsZero() {
		t.Fatal("first TouchLastUsed should set LastUsed")
	}
	for i := 0; i < 100; i++ {
		s.TouchLastUsed(tok.ID)
	}
	second := s.Get(tok.ID).LastUsed
	if !second.Equal(first) {
		t.Fatalf("rapid touches must be debounced (LastUsed unchanged within interval), got %v != %v", second, first)
	}
}
