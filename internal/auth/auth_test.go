package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"token abc123", "abc123"},
		{"Token abc123", "abc123"},
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"},
		{"token  spaced ", "spaced"},
		{"  token abc123  ", "abc123"},
		{"", ""},
		{"Basic abc123", ""},
		{"token ", ""},
		{"tokenABC", ""},
		{"noprefix", ""},
	}
	for _, tt := range tests {
		got := ExtractToken(tt.header)
		if got != tt.want {
			t.Errorf("ExtractToken(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "secret")

	secret, err := GenerateSecret(path)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	if len(secret) != 64 {
		t.Fatalf("expected 64-char hex string, got len %d", len(secret))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading secret file: %v", err)
	}
	if string(data) != secret {
		t.Fatal("file content does not match returned secret")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}
}

func TestGenerateSecretUniqueness(t *testing.T) {
	dir := t.TempDir()
	s1, _ := GenerateSecret(filepath.Join(dir, "s1"))
	s2, _ := GenerateSecret(filepath.Join(dir, "s2"))
	if s1 == s2 {
		t.Fatal("two generated secrets should not be equal")
	}
}
