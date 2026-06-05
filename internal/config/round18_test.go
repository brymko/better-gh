package config

import (
	"os"
	"testing"
)

// Round-18 J: EnsureDir must tighten a PRE-EXISTING config dir to 0700, not just newly-created
// ones (os.MkdirAll is a no-op on an existing looser-mode dir, leaving filenames/sizes/mtimes
// readable by other local users).
func TestSec_R18_EnsureDirTightensExisting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root: permission bits not enforced")
	}
	dir := t.TempDir() + "/bgh"
	if err := os.MkdirAll(dir, 0o755); err != nil { // pre-existing loose dir (umask 022)
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // ensure it really is 0755 regardless of umask
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("EnsureDir left dir mode %o, want 0700", perm)
	}
}
