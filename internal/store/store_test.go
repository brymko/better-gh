package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

func testPolicy() policy.Policy {
	return policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateAndLookup(t *testing.T) {
	s := openTestStore(t)

	tok, secret, err := s.Create("ci-bot", testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "ci-bot" {
		t.Fatalf("expected name ci-bot, got %s", tok.Name)
	}
	if !strings.HasPrefix(secret, "bgh_") || len(secret) != 68 {
		t.Fatalf("expected bgh_-prefixed 64-hex secret (len 68), got %q (len %d)", secret, len(secret))
	}

	found := s.Lookup(secret)
	if found == nil {
		t.Fatal("Lookup returned nil")
	}
	if found.ID != tok.ID {
		t.Fatalf("ID mismatch: %s != %s", found.ID, tok.ID)
	}
}

func TestLookupNotFound(t *testing.T) {
	s := openTestStore(t)
	if s.Lookup("nonexistent") != nil {
		t.Fatal("expected nil for nonexistent secret")
	}
}

// Lookup must return a COPY, not a pointer into the token slice: a request uses the
// result after releasing the lock, and Delete shifts the slice in place. A live pointer
// would be clobbered — repointed to a different token's policy. This reproduces the bug
// deterministically (no timing): tokens created AFTER the victim mean deleting tokens
// created BEFORE it overwrites, in place, the slot Lookup pointed at.
func TestLookupReturnsCopyNotSlicePointer(t *testing.T) {
	s := openTestStore(t)
	var before []string
	for i := 0; i < 8; i++ {
		tok, _, err := s.Create(fmt.Sprintf("before-%d", i), testPolicy())
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, tok.ID)
	}
	victim, secret, err := s.Create("victim", policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}})
	if err != nil {
		t.Fatal(err)
	}
	victimID := victim.ID    // copy the value now; Create also returns a slice pointer
	for i := 0; i < 8; i++ { // tokens AFTER victim so its slot is overwritten on shift
		if _, _, err := s.Create(fmt.Sprintf("after-%d", i), testPolicy()); err != nil {
			t.Fatal(err)
		}
	}

	got := s.Lookup(secret)
	if got == nil || got.Name != "victim" {
		t.Fatalf("setup: victim lookup failed: %#v", got)
	}

	for _, id := range before {
		s.Delete(id) // shifts the slice in place, over the slot victim occupied
	}

	if got.Name != "victim" || got.ID != victimID || got.Policy.Defaults.Mode != policy.ModeAllow {
		t.Fatalf("Lookup result was clobbered by Delete (got %q/%s) — Lookup must return a copy", got.Name, got.ID)
	}
}

func TestList(t *testing.T) {
	s := openTestStore(t)

	s.Create("a", testPolicy())
	s.Create("b", testPolicy())

	tokens := s.List()
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestGetByNameAndID(t *testing.T) {
	s := openTestStore(t)
	tok, _, _ := s.Create("my-token", testPolicy())

	byName := s.Get("my-token")
	if byName == nil || byName.ID != tok.ID {
		t.Fatal("Get by name failed")
	}

	byID := s.Get(tok.ID)
	if byID == nil || byID.Name != "my-token" {
		t.Fatal("Get by ID failed")
	}
}

func TestRevoke(t *testing.T) {
	s := openTestStore(t)
	_, secret, _ := s.Create("tok", testPolicy())

	if !s.Revoke("tok") {
		t.Fatal("Revoke returned false")
	}

	if s.Lookup(secret) != nil {
		t.Fatal("revoked token should not be found by Lookup")
	}

	tok := s.Get("tok")
	if tok == nil || !tok.Revoked {
		t.Fatal("Get should still return revoked token with Revoked=true")
	}
}

func TestDelete(t *testing.T) {
	s := openTestStore(t)
	s.Create("tok", testPolicy())

	if !s.Delete("tok") {
		t.Fatal("Delete returned false")
	}

	if s.Get("tok") != nil {
		t.Fatal("deleted token should not be found")
	}
	if len(s.List()) != 0 {
		t.Fatal("expected empty list after delete")
	}
}

func TestDeleteNonexistent(t *testing.T) {
	s := openTestStore(t)
	if s.Delete("nonexistent") {
		t.Fatal("Delete should return false for nonexistent token")
	}
}

func TestRevokeNonexistent(t *testing.T) {
	s := openTestStore(t)
	if s.Revoke("nonexistent") {
		t.Fatal("Revoke should return false for nonexistent token")
	}
}

func TestGetNonexistent(t *testing.T) {
	s := openTestStore(t)
	if s.Get("nonexistent") != nil {
		t.Fatal("Get should return nil for nonexistent token")
	}
}

func TestLookupMultipleTokens(t *testing.T) {
	s := openTestStore(t)
	_, s1, _ := s.Create("tok-1", testPolicy())
	_, s2, _ := s.Create("tok-2", testPolicy())

	tok1 := s.Lookup(s1)
	tok2 := s.Lookup(s2)
	if tok1 == nil || tok1.Name != "tok-1" {
		t.Fatal("lookup for tok-1 failed")
	}
	if tok2 == nil || tok2.Name != "tok-2" {
		t.Fatal("lookup for tok-2 failed")
	}
}

func TestTouchLastUsed(t *testing.T) {
	s := openTestStore(t)
	tok, _, _ := s.Create("tok", testPolicy())

	if !tok.LastUsed.IsZero() {
		t.Fatal("LastUsed should initially be zero")
	}

	s.TouchLastUsed(tok.ID)

	updated := s.Get(tok.ID)
	if updated.LastUsed.IsZero() {
		t.Fatal("LastUsed should be updated after TouchLastUsed")
	}
}

func TestTouchLastUsedNonexistent(t *testing.T) {
	s := openTestStore(t)
	s.TouchLastUsed("nonexistent-id")
}

func TestOpenCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	os.WriteFile(path, []byte("not json"), 0o644)

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestPolicyPreservedInToken(t *testing.T) {
	s := openTestStore(t)
	pol := policy.Policy{
		Defaults: policy.Defaults{
			Mode: policy.ModeDeny,
			Unscoped: map[string]policy.Access{
				"user": policy.AccessRead,
			},
		},
		Repo: []policy.RepoRule{{
			Name:   "org/repo",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"pulls": policy.AccessReadWrite,
			},
		}},
	}
	tok, _, _ := s.Create("full-policy", pol)

	retrieved := s.Get(tok.ID)
	if retrieved.Policy.Defaults.Unscoped["user"] != policy.AccessRead {
		t.Fatal("unscoped user=read not preserved")
	}
	if retrieved.Policy.Repo[0].Permissions["pulls"] != policy.AccessReadWrite {
		t.Fatal("repo permissions not preserved")
	}
}

func TestPersistencePreservesPermissionsAndUnscoped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	s1, _ := Open(path)
	pol := policy.Policy{
		Defaults: policy.Defaults{
			Mode: policy.ModeDeny,
			Unscoped: map[string]policy.Access{
				"user":   policy.AccessRead,
				"search": policy.AccessRead,
			},
		},
		Org: []policy.OrgRule{{
			Name:   "org",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"pulls": policy.AccessReadWrite,
			},
		}},
		Repo: []policy.RepoRule{{
			Name:   "org/repo",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"actions": policy.AccessNone,
				"issues":  policy.AccessReadWrite,
			},
		}},
	}
	s1.Create("round-trip", pol)

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	tok := s2.Get("round-trip")
	if tok == nil {
		t.Fatal("token not found after reopen")
	}

	if tok.Policy.Defaults.Unscoped["user"] != policy.AccessRead {
		t.Fatal("unscoped user=read lost on round-trip")
	}
	if tok.Policy.Defaults.Unscoped["search"] != policy.AccessRead {
		t.Fatal("unscoped search=read lost on round-trip")
	}
	if tok.Policy.Org[0].Permissions["pulls"] != policy.AccessReadWrite {
		t.Fatal("org pulls=read-write lost on round-trip")
	}
	if tok.Policy.Repo[0].Permissions["actions"] != policy.AccessNone {
		t.Fatal("repo actions=none lost on round-trip")
	}
	if tok.Policy.Repo[0].Permissions["issues"] != policy.AccessReadWrite {
		t.Fatal("repo issues=read-write lost on round-trip")
	}
}

func TestSec_LookupReturnsPointerIntoSlice(t *testing.T) {
	// Finding 9: Lookup returns a pointer into the tokens slice.
	// Concurrent Create can reallocate the slice, dangling the pointer.
	s := openTestStore(t)
	_, secret, _ := s.Create("tok-1", testPolicy())

	tok := s.Lookup(secret)
	if tok == nil {
		t.Fatal("expected token")
	}

	// tok is a pointer into s.tokens. If we create enough tokens
	// to force a reallocation, tok could dangle.
	name := tok.Name // capture before potential realloc
	for i := 0; i < 100; i++ {
		s.Create(fmt.Sprintf("tok-fill-%d", i), testPolicy())
	}

	// In Go, this won't crash (old backing array is kept alive by GC)
	// but the pointer may now refer to stale data if the slice was
	// reallocated and the old slot was reused. Verify it still works:
	if tok.Name != name {
		t.Logf("VULNERABLE: Lookup pointer returned stale data after slice realloc (Finding 9)")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	s1, _ := Open(path)
	s1.Create("persist-test", testPolicy())

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tokens := s2.List()
	if len(tokens) != 1 || tokens[0].Name != "persist-test" {
		t.Fatalf("persistence failed: got %d tokens", len(tokens))
	}
}
