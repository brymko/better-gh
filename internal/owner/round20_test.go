package owner

import (
	"path/filepath"
	"testing"
)

// Round-20: SetFallbackOwner is set-once — the TOFU fallback-owner binding (which gates who may claim
// a pre-seeded deployment) must not be overwritable by a later call.
func TestR20_SetFallbackOwnerSetOnce(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "owner.json"), "fallback-token")
	if err != nil {
		t.Fatal(err)
	}
	s.SetFallbackOwner("alice")
	s.SetFallbackOwner("attacker")
	if got := s.FallbackOwner(); got != "alice" {
		t.Fatalf("SetFallbackOwner must be set-once, got %q want alice", got)
	}
}
