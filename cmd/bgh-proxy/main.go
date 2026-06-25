package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/auth"
	"better-gh/internal/config"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/loginflow"
	"better-gh/internal/nodecache"
	"better-gh/internal/oauth"
	"better-gh/internal/owner"
	"better-gh/internal/policy"
	"better-gh/internal/proxy"
	"better-gh/internal/store"
	"better-gh/internal/tlsgen"
	"better-gh/internal/web"

	"github.com/BurntSushi/toml"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "login":
		err = cmdLogin(os.Args[2:])
	case "serve":
		configPath := ""
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--config" && i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			}
		}
		err = cmdServe(configPath)
	case "token":
		err = cmdToken(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `bgh-proxy — transparent GitHub API proxy with policy enforcement

Usage:
  bgh-proxy init                    Generate config, policy, and TLS certs
  bgh-proxy login [--client-id ID] [--scopes "repo read:org"]
                                    Obtain the upstream GitHub token via device flow
  bgh-proxy serve [--config path]   Start the proxy
  bgh-proxy token <subcommand>      Manage proxy tokens

Token subcommands:
  token create --name <name> [--default deny|allow]
    [--org <org>=<access>]...
    [--repo <owner/repo>=<access>]...
    [--org-perm <org>:<resource>=<access>]...
    [--repo-perm <owner/repo>:<resource>=<access>]...
    [--unscoped <category>=<access>]...
  token list
  token show <name-or-id>
  token revoke <name-or-id>
  token delete <name-or-id>

Resources: pulls, issues, contents, actions, releases, commits, branches, checks, comments, hooks, deployments, pages, keys, metadata
  (the Git Data API /repos/o/r/git/* is governed by branches [refs/tags], contents [blobs/trees], or commits)
  A misspelled --repo-perm key is rejected (it would otherwise silently fall back to base access).
  --repo-perm/--org-perm without a matching --repo/--org create a base-'none' rule (only the named
  resource is granted); pass --repo owner/repo=read to also grant a read base.
Unscoped categories: user, search, gists, notifications, events, meta

`)
}

func cmdInit() error {
	dir := config.DefaultDir()
	if err := config.EnsureDir(dir); err != nil {
		return err
	}

	if _, err := tlsgen.EnsureCerts(dir); err != nil {
		return fmt.Errorf("generating TLS certs: %w", err)
	}

	policyPath := filepath.Join(dir, "policy.toml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		example := `[defaults]
mode = "deny"

# [defaults.unscoped]
# user = "read"
# search = "read"

# [[org]]
# name = "my-company"
# access = "read"

# [[repo]]
# name = "my-company/frontend"
# access = "read-write"
# [repo.permissions]
# pulls = "read-write"
# actions = "none"
`
		if err := os.WriteFile(policyPath, []byte(example), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "bgh-proxy: example policy written to %s\n", policyPath)
	}

	configPath := filepath.Join(dir, "config.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		example := `bind = "127.0.0.1:7843"
admin_bind = "127.0.0.1:7844"  # plain HTTP for admin UI
socket = "~/.config/bgh/proxy.sock"
mode = "socket"        # "socket", "ghe", or "both"

# Upstream GitHub token (one of):
#   - set BGH_GITHUB_TOKEN env var, or
#   - github_token = "..." below, or
#   - run 'bgh-proxy login' (device flow, like gh — no setup needed)
# github_token = "..."
# oauth_client_id = "Iv1...."   # optional: your own OAuth App for 'bgh-proxy login' (defaults to gh's)
# oauth_scopes = "repo read:org gist workflow"

audit_log = "~/.config/bgh/audit.jsonl"
policy_file = "~/.config/bgh/policy.toml"
`
		if err := os.WriteFile(configPath, []byte(example), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "bgh-proxy: example config written to %s\n", configPath)
	}

	fmt.Fprintf(os.Stderr, "\nbgh-proxy: initialization complete\n")
	return nil
}

// ghCLIClientID is the GitHub CLI's public OAuth App client id. Using it makes
// `bgh-proxy login` behave like `gh auth login` with no OAuth App to register — the
// device flow authorizes the same "GitHub CLI" app and yields the same kind of token.
// Override with --client-id / BGH_OAUTH_CLIENT_ID / oauth_client_id to use your own app.
const ghCLIClientID = "178c6fc778ccc68e1d6a"
const ghCLIScopes = "repo read:org gist workflow"

func cmdLogin(args []string) error {
	clientID, scopes := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--client-id":
			if i+1 >= len(args) {
				return fmt.Errorf("--client-id requires a value")
			}
			i++
			clientID = args[i]
		case "--scopes":
			if i+1 >= len(args) {
				return fmt.Errorf("--scopes requires a value")
			}
			i++
			scopes = args[i]
		default:
			return fmt.Errorf("unknown flag: %s", args[i])
		}
	}

	if clientID == "" {
		clientID = os.Getenv("BGH_OAUTH_CLIENT_ID")
	}
	// Fall back to oauth_client_id / oauth_scopes in config.toml (without requiring a
	// token, which cmdServe's config.Load would).
	if data, err := os.ReadFile(filepath.Join(config.DefaultDir(), "config.toml")); err == nil {
		var p struct {
			OAuthClientID string `toml:"oauth_client_id"`
			OAuthScopes   string `toml:"oauth_scopes"`
		}
		if toml.Unmarshal(data, &p) == nil {
			if clientID == "" {
				clientID = p.OAuthClientID
			}
			if scopes == "" {
				scopes = p.OAuthScopes
			}
		}
	}
	if clientID == "" {
		// No app configured: mimic the gh CLI using its public OAuth app.
		clientID = ghCLIClientID
		if scopes == "" {
			scopes = ghCLIScopes
		}
	}
	if scopes == "" {
		scopes = "repo read:org"
	}

	token, err := oauth.DeviceFlow(context.Background(), oauth.Config{
		ClientID: clientID,
		Scopes:   scopes,
		Client:   &http.Client{Timeout: 30 * time.Second},
		Out:      os.Stderr,
	})
	if err != nil {
		return err
	}

	path := config.GithubTokenFilePath()
	if err := config.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return fmt.Errorf("storing token: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\nbgh-proxy: authorized. Upstream token stored at %s\n  Start the proxy with: bgh-proxy serve\n", path)
	return nil
}

func cmdServe(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// Tighten the config/secret dir to 0700 before any component writes secrets into it,
	// even if it pre-exists with a looser mode (round-18 J).
	if err := config.EnsureDir(config.DefaultDir()); err != nil {
		return fmt.Errorf("securing config directory: %w", err)
	}

	storePath := filepath.Join(config.DefaultDir(), "tokens.json")
	tokenStore, err := store.Open(storePath)
	if err != nil {
		return fmt.Errorf("opening token store: %w", err)
	}

	// Deployment owner + captured custodian token. The first GitHub sign-in (web or
	// `gh auth login`) claims the deployment and captures its token here; cfg.GithubToken
	// (if set) is the fallback custodian until then.
	ownerStore, err := owner.Open(filepath.Join(config.DefaultDir(), "owner.json"), cfg.GithubToken)
	if err != nil {
		return fmt.Errorf("opening owner store: %w", err)
	}
	if err := validatePublicGHEConfig(cfg); err != nil {
		return err
	}
	if !ownerStore.Claimed() && cfg.GithubToken == "" {
		slog.Warn("no custodian yet — sign in via the web UI or `gh auth login` to provision the proxy")
	} else if ownerStore.Claimed() {
		slog.Info("deployment owner", "login", ownerStore.Login())
	}

	auditLogger := audit.NewLogger(cfg.AuditLog)

	adminSecretPath := filepath.Join(config.DefaultDir(), "admin-secret")
	adminSecret, err := auth.LoadOrCreateSecret(adminSecretPath)
	if err != nil {
		return fmt.Errorf("preparing admin secret: %w", err)
	}

	socketPolicy, err := policy.LoadFromFile(cfg.PolicyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	// Fail startup on a misspelled per-resource key in policy.toml rather than serve a fail-open
	// policy: an unknown [repo.permissions] key never matches a request, so a per-resource `none`
	// under a typo would silently degrade to the rule's base access (round-19 D2).
	if err := socketPolicy.ValidateResourceKeys(); err != nil {
		return fmt.Errorf("invalid policy %s: %w", cfg.PolicyFile, err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		// Re-check same-host redirect targets against the request's policy so a redirect
		// (e.g. a renamed/moved repo's 301) can't be followed into a denied repo.
		CheckRedirect: proxy.EnforceRedirectPolicy,
	}
	nodeCache := nodecache.New(30 * time.Minute)

	// The GraphQL response filter IS the read-isolation boundary. Running without it
	// silently degrades to fail-open (viewer/search/org enumeration reads forwarded
	// unredacted), so refuse to start rather than serve degraded. The schema is embedded,
	// so this only fires on a build/corruption fault.
	gqlSchema, err := gqlfilter.Load()
	if err != nil {
		return fmt.Errorf("loading embedded graphql schema (required for read isolation): %w", err)
	}

	errCh := make(chan error, 3)

	webHandler := web.NewHandler(tokenStore, adminSecret)
	{
		adminMux := http.NewServeMux()
		adminMux.Handle("/", webHandler)
		ln, err := net.Listen("tcp", cfg.AdminBind)
		if err != nil {
			return fmt.Errorf("listening on admin %s: %w", cfg.AdminBind, err)
		}
		fmt.Fprintf(os.Stderr, "bgh-proxy: admin UI: http://%s/\n", cfg.AdminBind)
		fmt.Fprintf(os.Stderr, "bgh-proxy: admin secret written to %s\n", adminSecretPath)
		if !isLoopback(cfg.AdminBind) {
			slog.Warn("admin API bound to non-loopback address — credentials transmitted in cleartext", "bind", cfg.AdminBind)
		}
		go func() {
			errCh <- (&http.Server{
				Handler:      adminMux,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  60 * time.Second,
			}).Serve(ln)
		}()
	}

	if cfg.Mode == "socket" || cfg.Mode == "both" {
		socketHandler := &proxy.Handler{
			Custodian:    ownerStore.Token,
			Store:        tokenStore,
			Audit:        auditLogger,
			Client:       httpClient,
			Mode:         proxy.SocketMode,
			SocketPolicy: socketPolicy,
			NodeCache:    nodeCache,
			GQLFilter:    gqlSchema,
			NpmUpstream:  cfg.NpmUpstream,
		}

		os.Remove(cfg.Socket)
		// Create the socket with 0600 from the start (umask) so there is no window in
		// which another local user could connect; then enforce it and fail hard if that
		// does not hold. With 0600, only the owner can connect even on a shared dir.
		oldUmask := syscall.Umask(0o177)
		ln, err := net.Listen("unix", cfg.Socket)
		syscall.Umask(oldUmask)
		if err != nil {
			return fmt.Errorf("listening on unix socket: %w", err)
		}
		if err := os.Chmod(cfg.Socket, 0o600); err != nil {
			ln.Close()
			os.Remove(cfg.Socket)
			return fmt.Errorf("securing socket permissions: %w", err)
		}

		fmt.Fprintf(os.Stderr, "bgh-proxy: listening on unix://%s\n", cfg.Socket)
		fmt.Fprintf(os.Stderr, "bgh-proxy: setup gh (socket mode):\n\n  gh config set http_unix_socket %s\n\n", cfg.Socket)

		go func() {
			errCh <- (&http.Server{
				Handler:      socketHandler,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 120 * time.Second,
				IdleTimeout:  120 * time.Second,
			}).Serve(ln)
		}()
	}

	if cfg.Mode == "ghe" || cfg.Mode == "both" {
		gheHandler := &proxy.Handler{
			Custodian:   ownerStore.Token,
			Store:       tokenStore,
			Audit:       auditLogger,
			Client:      httpClient,
			Mode:        proxy.GHEMode,
			NodeCache:   nodeCache,
			GQLFilter:   gqlSchema,
			NpmUpstream: cfg.NpmUpstream,
		}

		// /login/* serves the OAuth identity-provider flow so a client can run the normal
		// `gh auth login` against the proxy. It mints a scoped proxy token after the operator
		// proves they own the custodian token via GitHub's device flow. Mounted ahead of the
		// proxy (the proxy 401s anything without a token; these ARE the token-acquisition
		// endpoints). Uses a plain client — no policy/redirect rewriting — for github.com.
		// Honor the documented oauth_client_id / oauth_scopes config keys for the sign-in IdP too
		// (not just `bgh-proxy login`): an operator who narrows oauth_scopes to shrink the captured
		// custodian's reach now actually gets it (round-12 audit M4). Empty → gh's public app / its
		// default scopes (loginflow.NewHandler fills the scope default).
		oauthClientID := cfg.OAuthClientID
		if oauthClientID == "" {
			oauthClientID = ghCLIClientID
		}
		loginHandler := loginflow.NewHandler(&loginflow.Handler{
			Store:         tokenStore,
			Owner:         ownerStore,
			FallbackToken: cfg.GithubToken,
			OAuthClientID: oauthClientID,
			OAuthScopes:   cfg.OAuthScopes,
			HTTPClient:    &http.Client{Timeout: 30 * time.Second},
			ExternalURL:   cfg.ExternalURL,
		})
		gheMux := http.NewServeMux()
		gheMux.Handle("/login/", loginHandler) // OAuth IdP for `gh auth login`
		gheMux.Handle("/ui", loginHandler)     // web "create a token" page
		gheMux.Handle("/ui/", loginHandler)    // its /ui/api/* endpoints
		gheMux.Handle("/", gheHandler)

		certs, err := tlsgen.EnsureCerts(cfg.TLSDir)
		if err != nil {
			return fmt.Errorf("ensuring TLS certs: %w", err)
		}

		tlsCert, err := tls.LoadX509KeyPair(certs.ServerCertPath, certs.ServerKeyPath)
		if err != nil {
			return fmt.Errorf("loading TLS cert: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}

		ln, err := tls.Listen("tcp", cfg.Bind, tlsConfig)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", cfg.Bind, err)
		}

		fmt.Fprintf(os.Stderr, "bgh-proxy: listening on https://%s\n", cfg.Bind)
		fmt.Fprintf(os.Stderr, "bgh-proxy: setup gh (GHE mode) — interactive login (mints a scoped token):\n\n")
		fmt.Fprintf(os.Stderr, "  gh auth login --hostname %s   # then pick a policy in the browser\n\n", cfg.Bind)
		fmt.Fprintf(os.Stderr, "bgh-proxy: or pre-mint a token and paste it:\n\n")
		fmt.Fprintf(os.Stderr, "  bgh-proxy token create --name my-client --default deny --org my-company=read\n")
		fmt.Fprintf(os.Stderr, "  echo <secret> | gh auth login --hostname %s --with-token\n\n", cfg.Bind)

		go func() {
			errCh <- (&http.Server{
				Handler:      gheMux,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 120 * time.Second,
				IdleTimeout:  120 * time.Second,
			}).Serve(ln)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		fmt.Fprintf(os.Stderr, "\nbgh-proxy: received %v, shutting down\n", sig)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	if cfg.Mode == "socket" || cfg.Mode == "both" {
		os.Remove(cfg.Socket)
	}

	return nil
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing token subcommand")
	}

	ac := &adminClient{}
	if err := ac.init(); err != nil {
		return err
	}

	switch args[0] {
	case "create":
		return tokenCreate(ac, args[1:])
	case "list":
		return tokenList(ac)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: bgh-proxy token show <name-or-id>")
		}
		return tokenShow(ac, args[1])
	case "revoke":
		if len(args) < 2 {
			return fmt.Errorf("usage: bgh-proxy token revoke <name-or-id>")
		}
		return tokenRevoke(ac, args[1])
	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: bgh-proxy token delete <name-or-id>")
		}
		return tokenDelete(ac, args[1])
	default:
		return fmt.Errorf("unknown token subcommand: %s", args[0])
	}
}

type adminClient struct {
	baseURL string
	secret  string
	http    *http.Client
}

func (c *adminClient) init() error {
	secretPath := filepath.Join(config.DefaultDir(), "admin-secret")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return fmt.Errorf("reading admin secret from %s: %w (is the server running?)", secretPath, err)
	}
	c.secret = strings.TrimSpace(string(data))

	cfg := &config.Config{AdminBind: "127.0.0.1:7844"}
	cfgPath := filepath.Join(config.DefaultDir(), "config.toml")
	if cfgData, err := os.ReadFile(cfgPath); err == nil {
		// just need admin_bind from config
		type partial struct {
			AdminBind string `toml:"admin_bind"`
		}
		var p partial
		if err := toml.Unmarshal(cfgData, &p); err == nil && p.AdminBind != "" {
			cfg.AdminBind = p.AdminBind
		}
	}
	c.baseURL = "http://" + cfg.AdminBind
	c.http = &http.Client{}
	return nil
}

func (c *adminClient) do(method, path string, body any) (json.RawMessage, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to admin API: %w (is the server running?)", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		json.Unmarshal(respBody, &errResp)
		if msg, ok := errResp["error"]; ok {
			return nil, fmt.Errorf("API error: %s", msg)
		}
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}
	return respBody, nil
}

func tokenCreate(c *adminClient, args []string) error {
	name := ""
	defaultMode := "deny"
	type rule struct {
		Name        string            `json:"name"`
		Access      string            `json:"access"`
		Permissions map[string]string `json:"permissions,omitempty"`
	}
	var orgRules, repoRules []rule
	unscopedMap := map[string]string{}

	orgPerms := map[string]map[string]string{}
	repoPerms := map[string]map[string]string{}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 >= len(args) {
				return fmt.Errorf("--name requires a value")
			}
			i++
			name = args[i]
		case "--default":
			if i+1 >= len(args) {
				return fmt.Errorf("--default requires a value")
			}
			i++
			defaultMode = args[i]
		case "--org":
			if i+1 >= len(args) {
				return fmt.Errorf("--org requires a value (org=access)")
			}
			i++
			n, a, err := parseRuleStr(args[i])
			if err != nil {
				return fmt.Errorf("--org: %w", err)
			}
			orgRules = append(orgRules, rule{Name: n, Access: a})
		case "--repo":
			if i+1 >= len(args) {
				return fmt.Errorf("--repo requires a value (owner/repo=access)")
			}
			i++
			n, a, err := parseRuleStr(args[i])
			if err != nil {
				return fmt.Errorf("--repo: %w", err)
			}
			repoRules = append(repoRules, rule{Name: n, Access: a})
		case "--org-perm":
			if i+1 >= len(args) {
				return fmt.Errorf("--org-perm requires a value (org:resource=access)")
			}
			i++
			scope, resource, access, err := parsePermStr(args[i])
			if err != nil {
				return fmt.Errorf("--org-perm: %w", err)
			}
			if orgPerms[scope] == nil {
				orgPerms[scope] = map[string]string{}
			}
			orgPerms[scope][resource] = access
		case "--repo-perm":
			if i+1 >= len(args) {
				return fmt.Errorf("--repo-perm requires a value (owner/repo:resource=access)")
			}
			i++
			scope, resource, access, err := parsePermStr(args[i])
			if err != nil {
				return fmt.Errorf("--repo-perm: %w", err)
			}
			if repoPerms[scope] == nil {
				repoPerms[scope] = map[string]string{}
			}
			repoPerms[scope][resource] = access
		case "--unscoped":
			if i+1 >= len(args) {
				return fmt.Errorf("--unscoped requires a value (category=access)")
			}
			i++
			cat, acc, err := parseRuleStr(args[i])
			if err != nil {
				return fmt.Errorf("--unscoped: %w", err)
			}
			unscopedMap[cat] = acc
		default:
			return fmt.Errorf("unknown flag: %s", args[i])
		}
	}

	if name == "" {
		return fmt.Errorf("--name is required")
	}

	for i := range orgRules {
		if p, ok := orgPerms[orgRules[i].Name]; ok {
			orgRules[i].Permissions = p
			delete(orgPerms, orgRules[i].Name)
		}
	}
	// A --org-perm/--repo-perm with no matching --org/--repo base rule creates the rule with base
	// access "none" (least privilege), so e.g. `--repo-perm o/r:pulls=read-write` grants ONLY pulls,
	// not whole-repo read. Defaulting the base to "read" (the old behavior) silently widened the grant
	// — every other resource of that repo became readable — and contradicted socket-mode policy.toml,
	// where a [repo.permissions] block with no `access` line defaults the base to the "none" zero
	// value (round-19 D1). Specify `--repo o/r=read` explicitly to also grant a read base.
	for orgName, p := range orgPerms {
		orgRules = append(orgRules, rule{Name: orgName, Access: "none", Permissions: p})
	}

	for i := range repoRules {
		if p, ok := repoPerms[repoRules[i].Name]; ok {
			repoRules[i].Permissions = p
			delete(repoPerms, repoRules[i].Name)
		}
	}
	for repoName, p := range repoPerms {
		repoRules = append(repoRules, rule{Name: repoName, Access: "none", Permissions: p})
	}

	polBody := map[string]any{
		"default": defaultMode,
		"org":     orgRules,
		"repo":    repoRules,
	}
	if len(unscopedMap) > 0 {
		polBody["unscoped"] = unscopedMap
	}

	body := map[string]any{
		"name":   name,
		"policy": polBody,
	}

	resp, err := c.do("POST", "/api/tokens", body)
	if err != nil {
		return err
	}

	var result struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(resp, &result)
	fmt.Println(result.Secret)
	return nil
}

func tokenList(c *adminClient) error {
	resp, err := c.do("GET", "/api/tokens", nil)
	if err != nil {
		return err
	}

	var tokens []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
		LastUsed  string `json:"last_used"`
		Revoked   bool   `json:"revoked"`
	}
	json.Unmarshal(resp, &tokens)

	if len(tokens) == 0 {
		fmt.Fprintf(os.Stderr, "no tokens\n")
		return nil
	}
	fmt.Printf("%-12s %-20s %-10s %-20s %-20s\n", "ID", "NAME", "STATUS", "CREATED", "LAST USED")
	for _, t := range tokens {
		status := "active"
		if t.Revoked {
			status = "revoked"
		}
		lastUsed := t.LastUsed
		if lastUsed == "" {
			lastUsed = "-"
		}
		id := t.ID
		if len(id) > 12 {
			id = id[:12]
		}
		fmt.Printf("%-12s %-20s %-10s %-20s %-20s\n", id, t.Name, status, t.CreatedAt, lastUsed)
	}
	return nil
}

func tokenShow(c *adminClient, idOrName string) error {
	resp, err := c.do("GET", "/api/tokens/"+idOrName, nil)
	if err != nil {
		return err
	}

	var tok store.ProxyToken
	json.Unmarshal(resp, &tok)

	status := "active"
	if tok.Revoked {
		status = "revoked"
	}
	fmt.Printf("ID:       %s\n", tok.ID)
	fmt.Printf("Name:     %s\n", tok.Name)
	fmt.Printf("Status:   %s\n", status)
	fmt.Printf("Created:  %s\n", tok.CreatedAt.Format("2006-01-02 15:04:05"))
	if !tok.LastUsed.IsZero() {
		fmt.Printf("LastUsed: %s\n", tok.LastUsed.Format("2006-01-02 15:04:05"))
	}

	defaultStr, _ := tok.Policy.Defaults.Mode.MarshalText()
	fmt.Printf("Default:  %s\n", defaultStr)
	if len(tok.Policy.Defaults.Unscoped) > 0 {
		for cat, acc := range tok.Policy.Defaults.Unscoped {
			accessStr, _ := acc.MarshalText()
			fmt.Printf("Unscoped: %s=%s\n", cat, accessStr)
		}
	}
	for _, o := range tok.Policy.Org {
		accessStr, _ := o.Access.MarshalText()
		fmt.Printf("Org:      %s=%s\n", o.Name, accessStr)
		for res, acc := range o.Permissions {
			permStr, _ := acc.MarshalText()
			fmt.Printf("  Perm:   %s=%s\n", res, permStr)
		}
	}
	for _, r := range tok.Policy.Repo {
		accessStr, _ := r.Access.MarshalText()
		fmt.Printf("Repo:     %s=%s\n", r.Name, accessStr)
		for res, acc := range r.Permissions {
			permStr, _ := acc.MarshalText()
			fmt.Printf("  Perm:   %s=%s\n", res, permStr)
		}
	}
	return nil
}

func tokenRevoke(c *adminClient, idOrName string) error {
	_, err := c.do("DELETE", "/api/tokens/"+idOrName, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "token revoked\n")
	return nil
}

func tokenDelete(c *adminClient, idOrName string) error {
	// Route through the running server so its in-memory store is updated; a direct
	// file delete would be silently overwritten by the server's own writes.
	if _, err := c.do("DELETE", "/api/tokens/"+idOrName+"?hard=true", nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "token deleted\n")
	return nil
}

func parsePermStr(s string) (scope, resource, access string, err error) {
	colonIdx := strings.LastIndex(s, ":")
	if colonIdx < 0 {
		return "", "", "", fmt.Errorf("expected scope:resource=access, got %q", s)
	}
	scope = s[:colonIdx]
	rest := s[colonIdx+1:]
	parts := strings.SplitN(rest, "=", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("expected scope:resource=access, got %q", s)
	}
	resource = parts[0]
	access = parts[1]
	switch access {
	case "none", "read", "read-write", "readwrite", "write":
	default:
		return "", "", "", fmt.Errorf("unknown access level: %q", access)
	}
	return scope, resource, access, nil
}

func parseRuleStr(s string) (string, string, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected name=access, got %q", s)
	}
	switch parts[1] {
	case "none", "read", "read-write", "readwrite", "write":
	default:
		return "", "", fmt.Errorf("unknown access level: %q", parts[1])
	}
	return parts[0], parts[1], nil
}

func portFromAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

func validatePublicGHEConfig(cfg *config.Config) error {
	if cfg.Mode != "ghe" && cfg.Mode != "both" {
		return nil
	}
	publicLoginSurface := !isLoopback(cfg.Bind) || strings.TrimSpace(cfg.ExternalURL) != ""
	if !publicLoginSurface {
		return nil
	}
	if ext := strings.TrimSpace(cfg.ExternalURL); ext != "" {
		u, err := url.Parse(ext)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("invalid external_url %q: public GHE deployments require an https URL with a host", cfg.ExternalURL)
		}
		if !validPublicHostname(u.Hostname()) {
			return fmt.Errorf("invalid external_url %q: host %q is not a valid public TLS hostname", cfg.ExternalURL, u.Hostname())
		}
	}
	return nil
}

func validPublicHostname(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
