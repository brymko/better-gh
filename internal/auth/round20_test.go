package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// Round-20: LoadOrCreateSecret must return a STABLE secret across calls (not rotate it) and must FAIL
// CLOSED on an unreadable (non-IsNotExist) path rather than silently regenerate + overwrite it.
func TestR20_LoadOrCreateSecretStableAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin-secret")

	s1, err := LoadOrCreateSecret(path)
	if err != nil || s1 == "" {
		t.Fatalf("first LoadOrCreateSecret: %q %v", s1, err)
	}
	s2, err := LoadOrCreateSecret(path)
	if err != nil || s2 != s1 {
		t.Fatalf("LoadOrCreateSecret rotated a stable secret: %q vs %q (%v)", s1, s2, err)
	}

	// An unreadable existing path (a directory → EISDIR, not IsNotExist) must error, not rotate.
	dirPath := filepath.Join(dir, "as-dir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecret(dirPath); err == nil {
		t.Fatal("LoadOrCreateSecret must fail closed on an unreadable path, not rotate")
	}

	// An empty existing secret file must error (anomalous), not silently regenerate.
	emptyPath := filepath.Join(dir, "empty-secret")
	if err := os.WriteFile(emptyPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecret(emptyPath); err == nil {
		t.Fatal("LoadOrCreateSecret must error on an empty secret file")
	}
}
