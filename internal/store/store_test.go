package store

import (
	"path/filepath"
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
	if len(secret) != 64 {
		t.Fatalf("expected 64-char hex secret, got len %d", len(secret))
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
