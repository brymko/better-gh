package owner

import (
	"os"
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

	// A pre-seeded fallback binds the claim to the fallback custodian's own GitHub identity:
	// before that identity is resolved, NO sign-in may claim (fail closed — round-18 G).
	if claimed, ok, _ := s.SignIn("Alice", "gho_alice1"); ok || claimed {
		t.Fatal("claim must be refused while the fallback owner is unresolved")
	}
	s.SetFallbackOwner("Alice") // the pre-seeded token belongs to Alice

	// First sign-in (as the fallback owner) claims the deployment and captures the token.
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

// Round-18 G: a pre-seeded (fallback) deployment may be claimed ONLY by the fallback
// custodian's own GitHub account. A network-reachable stranger who signs in first must NOT
// be able to claim ownership / swap the custodian.
func TestSec_R18_FallbackClaimBoundToCustodianOwner(t *testing.T) {
	path := t.TempDir() + "/owner.json"
	s, _ := Open(path, "fallback-tok")
	s.SetFallbackOwner("operator") // the pre-seeded token belongs to "operator"

	// A different account that reaches the IdP first cannot claim.
	if claimed, ok, err := s.SignIn("attacker", "gho_attacker"); ok || claimed || err != nil {
		t.Fatalf("stranger must not claim a pre-seeded deployment: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
	if s.Claimed() || s.Token() != "fallback-tok" {
		t.Fatalf("rejected claim mutated state: claimed=%v token=%q", s.Claimed(), s.Token())
	}

	// The fallback custodian's own account claims it normally.
	if claimed, ok, err := s.SignIn("operator", "gho_operator"); !ok || !claimed || err != nil {
		t.Fatalf("fallback owner should claim: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
	if s.Login() != "operator" || s.Token() != "gho_operator" {
		t.Fatalf("after claim: login=%q token=%q", s.Login(), s.Token())
	}
}

// Round-18 G: with a fallback configured but its owner not yet resolved, every claim is
// refused (fail closed) — an unverified fallback must never be claimable.
func TestSec_R18_UnverifiedFallbackFailsClosed(t *testing.T) {
	path := t.TempDir() + "/owner.json"
	s, _ := Open(path, "fallback-tok")
	if claimed, ok, err := s.SignIn("anyone", "gho_anyone"); ok || claimed || err != nil {
		t.Fatalf("unverified fallback must reject claims: claimed=%v ok=%v err=%v", claimed, ok, err)
	}
}

// Round-18 I: a persist failure during SignIn must leave the in-memory owner/custodian
// state unchanged (no silent claim / custodian swap diverging from disk).
func TestSec_R18_SignInPersistFailureNoMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	dir := t.TempDir()
	s, err := Open(dir+"/owner.json", "") // no fallback → open TOFU; file absent → Open ok
	if err != nil {
		t.Fatal(err)
	}
	// Make the parent dir unwritable so persist (the temp-file write) fails mid-claim.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	claimed, ok, serr := s.SignIn("bob", "gho_bob")
	if serr == nil || ok {
		t.Fatalf("expected persist failure: claimed=%v ok=%v err=%v", claimed, ok, serr)
	}
	if s.Claimed() || s.Login() != "" || s.Token() != "" {
		t.Fatalf("failed claim mutated in-memory state: claimed=%v login=%q token=%q", s.Claimed(), s.Login(), s.Token())
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
