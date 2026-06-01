package owner

import (
	"testing"
)

func TestTOFUClaimMatchRefreshReject(t *testing.T) {
	path := t.TempDir() + "/owner.json"
	s, err := Open(path, "fallback-tok")
	if err != nil {
		t.Fatal(err)
	}

	// Unclaimed: not claimed, Token falls back, no owner login.
	if s.Claimed() || s.Login() != "" {
		t.Fatal("should start unclaimed")
	}
	if s.Token() != "fallback-tok" {
		t.Fatalf("unclaimed Token should be the fallback, got %q", s.Token())
	}

	// First sign-in claims the deployment and captures the token as custodian.
	claimed, ok, err := s.SignIn("Alice", "gho_alice1")
	if err != nil || !ok || !claimed {
		t.Fatalf("first sign-in should claim: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
	if s.Login() != "Alice" || s.Token() != "gho_alice1" {
		t.Fatalf("after claim: login=%q token=%q", s.Login(), s.Token())
	}

	// Same owner (case-insensitive) refreshes the captured token, does not re-claim.
	claimed, ok, err = s.SignIn("alice", "gho_alice2")
	if err != nil || !ok || claimed {
		t.Fatalf("same-owner sign-in should refresh, not claim: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
	if s.Token() != "gho_alice2" {
		t.Fatalf("token not refreshed: %q", s.Token())
	}

	// A different GitHub account is rejected (ok=false, nil err) and changes nothing.
	claimed, ok, err = s.SignIn("mallory", "gho_mallory")
	if err != nil || ok || claimed {
		t.Fatalf("non-owner must be rejected: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
	if s.Login() != "Alice" || s.Token() != "gho_alice2" {
		t.Fatalf("rejected sign-in mutated state: login=%q token=%q", s.Login(), s.Token())
	}
}

func TestPersistenceReload(t *testing.T) {
	path := t.TempDir() + "/owner.json"
	s, _ := Open(path, "")
	if _, _, err := s.SignIn("bob", "gho_bob"); err != nil {
		t.Fatal(err)
	}
	// A fresh Store (e.g. after restart) sees the claimed owner + captured token.
	s2, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Claimed() || s2.Login() != "bob" || s2.Token() != "gho_bob" {
		t.Fatalf("owner not persisted: claimed=%v login=%q token=%q", s2.Claimed(), s2.Login(), s2.Token())
	}
}
