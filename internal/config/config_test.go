package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`
bind = "127.0.0.1:9000"
admin_bind = "127.0.0.1:9001"
socket = "/tmp/test.sock"
github_token = "ghp_test"
audit_log = "/tmp/audit.jsonl"
policy_file = "/tmp/policy.toml"
mode = "socket"
`), 0o644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Bind != "127.0.0.1:9000" {
		t.Errorf("Bind = %q", cfg.Bind)
	}
	if cfg.AdminBind != "127.0.0.1:9001" {
		t.Errorf("AdminBind = %q", cfg.AdminBind)
	}
	if cfg.Socket != "/tmp/test.sock" {
		t.Errorf("Socket = %q", cfg.Socket)
	}
	if cfg.GithubToken != "ghp_test" {
		t.Errorf("GithubToken = %q", cfg.GithubToken)
	}
	if cfg.Mode != "socket" {
		t.Errorf("Mode = %q", cfg.Mode)
	}
}

func TestLoadEnvVarOverridesFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`github_token = "from-file"`), 0o644)

	t.Setenv("BGH_GITHUB_TOKEN", "from-env")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GithubToken != "from-env" {
		t.Fatalf("expected env var to win, got %q", cfg.GithubToken)
	}
}

func TestLoadMissingTokenReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir) // isolate DefaultDir so no stray github-token file is found
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`mode = "socket"`), 0o644)

	t.Setenv("BGH_GITHUB_TOKEN", "")
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for missing github token")
	}
}

func TestLoadTokenFromLoginFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BGH_GITHUB_TOKEN", "")
	bghDir := filepath.Join(home, ".config", "bgh")
	os.MkdirAll(bghDir, 0o700)
	os.WriteFile(filepath.Join(bghDir, "github-token"), []byte("gho_fromlogin\n"), 0o600)

	cfg, err := Load(filepath.Join(bghDir, "config.toml")) // no such file → defaults
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GithubToken != "gho_fromlogin" {
		t.Fatalf("expected token from login file, got %q", cfg.GithubToken)
	}
}

func TestLoadEnvOverridesLoginFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BGH_GITHUB_TOKEN", "gho_fromenv")
	bghDir := filepath.Join(home, ".config", "bgh")
	os.MkdirAll(bghDir, 0o700)
	os.WriteFile(filepath.Join(bghDir, "github-token"), []byte("gho_fromlogin"), 0o600)

	cfg, err := Load(filepath.Join(bghDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GithubToken != "gho_fromenv" {
		t.Fatalf("env should override login file, got %q", cfg.GithubToken)
	}
}

func TestLoadInvalidModeReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`
github_token = "ghp_test"
mode = "invalid"
`), 0o644)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestLoadValidModes(t *testing.T) {
	for _, mode := range []string{"socket", "ghe", "both"} {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")
		os.WriteFile(cfgPath, []byte(`
github_token = "ghp_test"
mode = "`+mode+`"
`), 0o644)

		cfg, err := Load(cfgPath)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if cfg.Mode != mode {
			t.Fatalf("expected mode %q, got %q", mode, cfg.Mode)
		}
	}
}

func TestLoadInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`{{{{invalid`), 0o644)

	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestLoadNonexistentFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "does-not-exist.toml")

	t.Setenv("BGH_GITHUB_TOKEN", "ghp_test")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bind != "127.0.0.1:7843" {
		t.Errorf("expected default bind, got %q", cfg.Bind)
	}
	if cfg.AdminBind != "127.0.0.1:7844" {
		t.Errorf("expected default admin_bind, got %q", cfg.AdminBind)
	}
	if cfg.Mode != "both" {
		t.Errorf("expected default mode=both, got %q", cfg.Mode)
	}
}

func TestLoadDefaultPaths(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`github_token = "ghp_test"`), 0o644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuditLog == "" {
		t.Error("AuditLog should have a default")
	}
	if cfg.PolicyFile == "" {
		t.Error("PolicyFile should have a default")
	}
	if cfg.TLSDir == "" {
		t.Error("TLSDir should have a default")
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()

	got := expandTilde("~/test/path")
	want := filepath.Join(home, "test/path")
	if got != want {
		t.Errorf("expandTilde(~/test/path) = %q, want %q", got, want)
	}

	got2 := expandTilde("/absolute/path")
	if got2 != "/absolute/path" {
		t.Errorf("expandTilde(/absolute/path) = %q, want unchanged", got2)
	}

	got3 := expandTilde("relative/path")
	if got3 != "relative/path" {
		t.Errorf("expandTilde(relative/path) = %q, want unchanged", got3)
	}
}

func TestLoadTildeExpansion(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte(`
github_token = "ghp_test"
audit_log = "~/audit.jsonl"
policy_file = "~/policy.toml"
socket = "~/proxy.sock"
`), 0o644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	home, _ := os.UserHomeDir()
	if cfg.AuditLog != filepath.Join(home, "audit.jsonl") {
		t.Errorf("AuditLog tilde not expanded: %q", cfg.AuditLog)
	}
	if cfg.PolicyFile != filepath.Join(home, "policy.toml") {
		t.Errorf("PolicyFile tilde not expanded: %q", cfg.PolicyFile)
	}
	if cfg.Socket != filepath.Join(home, "proxy.sock") {
		t.Errorf("Socket tilde not expanded: %q", cfg.Socket)
	}
}

func TestDefaultDir(t *testing.T) {
	dir := DefaultDir()
	if dir == "" {
		t.Fatal("DefaultDir should not be empty")
	}
	home, _ := os.UserHomeDir()
	if dir != filepath.Join(home, ".config", "bgh") {
		t.Errorf("DefaultDir = %q, want %q", dir, filepath.Join(home, ".config", "bgh"))
	}
}
