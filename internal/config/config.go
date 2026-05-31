package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Bind          string `toml:"bind"`
	AdminBind     string `toml:"admin_bind"`
	Socket        string `toml:"socket"`
	GithubToken   string `toml:"github_token"`
	OAuthClientID string `toml:"oauth_client_id"`
	OAuthScopes   string `toml:"oauth_scopes"`
	AuditLog      string `toml:"audit_log"`
	PolicyFile    string `toml:"policy_file"`
	TLSDir        string `toml:"tls_dir"`
	Mode          string `toml:"mode"`
}

func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "bgh")
}

// GithubTokenFilePath is where `bgh-proxy login` persists the upstream token.
func GithubTokenFilePath() string {
	return filepath.Join(DefaultDir(), "github-token")
}

func Load(path string) (*Config, error) {
	c := &Config{
		Bind:      "127.0.0.1:7843",
		AdminBind: "127.0.0.1:7844",
		Mode:      "both",
		Socket:    filepath.Join(DefaultDir(), "proxy.sock"),
	}

	if path == "" {
		path = filepath.Join(DefaultDir(), "config.toml")
	}

	if data, err := os.ReadFile(path); err == nil {
		if err := toml.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}

	// Upstream-token resolution order: env var, then github_token in config, then the
	// token file written by `bgh-proxy login`.
	if tok := os.Getenv("BGH_GITHUB_TOKEN"); tok != "" {
		c.GithubToken = tok
	} else if c.GithubToken == "" {
		if data, err := os.ReadFile(GithubTokenFilePath()); err == nil {
			c.GithubToken = strings.TrimSpace(string(data))
		}
	}

	if c.GithubToken == "" {
		return nil, fmt.Errorf("no GitHub token: run `bgh-proxy login`, set BGH_GITHUB_TOKEN, or set github_token in config")
	}

	if c.AuditLog == "" {
		c.AuditLog = filepath.Join(DefaultDir(), "audit.jsonl")
	}
	c.AuditLog = expandTilde(c.AuditLog)

	if c.PolicyFile == "" {
		c.PolicyFile = filepath.Join(DefaultDir(), "policy.toml")
	}
	c.PolicyFile = expandTilde(c.PolicyFile)

	if c.TLSDir == "" {
		c.TLSDir = DefaultDir()
	}
	c.TLSDir = expandTilde(c.TLSDir)

	c.Socket = expandTilde(c.Socket)

	switch c.Mode {
	case "socket", "ghe", "both":
	default:
		return nil, fmt.Errorf("invalid mode %q: must be socket, ghe, or both", c.Mode)
	}

	return c, nil
}

func expandTilde(s string) string {
	if strings.HasPrefix(s, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, s[2:])
	}
	return s
}
