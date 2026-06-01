package loginflow

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"better-gh/internal/oauth"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

const (
	githubBaseDefault = "https://github.com"
	apiBaseDefault    = "https://api.github.com"
	grantTTL          = 15 * time.Minute
	maxBody           = 1 << 20
)

//go:embed authorize.html
var authorizePage []byte

// Handler implements the proxy's OAuth identity-provider endpoints under /login/*. It runs a
// GitHub device flow to authenticate the operator, requires the resulting GitHub login to be
// the custodian token's owner, then mints a scoped bgh_ proxy token and returns it to gh.
type Handler struct {
	Store         *store.Store
	UpstreamToken string       // custodian token; its owner is the only login allowed to authorize
	OAuthClientID string       // gh's public app id; no registration needed
	OAuthScopes   string       // minimal scopes for the identity device flow (default "read:user")
	GitHubBaseURL string       // device-flow base; default https://github.com (overridden in tests)
	APIBaseURL    string       // viewer{login} base; default https://api.github.com (overridden in tests)
	HTTPClient    *http.Client // used for the inner GitHub calls
	ExternalURL   string       // public base URL clients reach the proxy at, e.g. https://vps.tailnet.ts.net
	// Set when behind a TLS-terminating front (tailscale serve, Caddy): the device-flow
	// verification_uri the proxy hands gh must point at the public URL, not the backend the
	// front forwards to. Empty → derive from the request Host (correct for direct serving).

	mux     *http.ServeMux
	grants  *grantStore
	ownerMu sync.Mutex
	owner   string // cached custodian-owner login
}

func NewHandler(h *Handler) *Handler {
	if h.GitHubBaseURL == "" {
		h.GitHubBaseURL = githubBaseDefault
	}
	if h.APIBaseURL == "" {
		h.APIBaseURL = apiBaseDefault
	}
	if h.OAuthScopes == "" {
		h.OAuthScopes = "read:user"
	}
	if h.HTTPClient == nil {
		h.HTTPClient = http.DefaultClient
	}
	h.grants = newGrantStore(grantTTL)

	m := http.NewServeMux()
	m.HandleFunc("POST /login/device/code", h.deviceCode)
	m.HandleFunc("POST /login/oauth/access_token", h.accessToken)
	m.HandleFunc("GET /login/oauth/authorize", h.authorizePageWeb)
	m.HandleFunc("GET /login/device", h.authorizePageDevice)
	m.HandleFunc("POST /login/api/begin", h.apiBegin)
	m.HandleFunc("POST /login/api/poll", h.apiPoll)
	m.HandleFunc("POST /login/api/approve", h.apiApprove)
	h.mux = m
	return h
}

func (h *Handler) Stop()                                            { h.grants.stop() }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// --- outer OAuth (gh <-> proxy) ---------------------------------------------------------

func (h *Handler) deviceCode(w http.ResponseWriter, r *http.Request) {
	g := &grant{flow: "device", userCode: randUserCode(), deviceCode: randHex(32), status: statusPending}
	h.grants.add(g)
	verURI := h.verificationBase(r) + "/login/device"
	jsonResp(w, http.StatusOK, map[string]any{
		"device_code":               g.deviceCode,
		"user_code":                 g.userCode,
		"verification_uri":          verURI,
		"verification_uri_complete": verURI + "?user_code=" + g.userCode,
		"expires_in":                int(grantTTL.Seconds()),
		"interval":                  5,
	})
}

// accessToken is what gh polls (device) or exchanges (web). It returns the minted bgh_ token
// once the grant is approved, or an OAuth device-flow status otherwise (HTTP 200 + {error}).
func (h *Handler) accessToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	deviceCode := r.PostForm.Get("device_code")
	code := r.PostForm.Get("code")

	var match func(*grant) bool
	switch {
	case deviceCode != "":
		match = byDeviceCode(deviceCode)
	case code != "":
		match = byAuthCode(code)
	default:
		jsonResp(w, http.StatusOK, map[string]string{"error": "invalid_request"})
		return
	}

	var secret, errCode, grantID string
	found := h.grants.withGrant(match, func(g *grant) {
		switch g.status {
		case statusApproved:
			secret, grantID = g.secret, g.id
		case statusDenied:
			errCode = "access_denied"
		default:
			errCode = "authorization_pending"
		}
	})
	if !found {
		// unknown/expired code: device flow reads this as the code having expired.
		jsonResp(w, http.StatusOK, map[string]string{"error": "expired_token"})
		return
	}
	if errCode != "" {
		jsonResp(w, http.StatusOK, map[string]string{"error": errCode})
		return
	}
	h.grants.remove(grantID) // one-time issuance: a replayed exchange can't re-fetch the secret
	jsonResp(w, http.StatusOK, map[string]string{
		"access_token": secret,
		"token_type":   "bearer",
		"scope":        "repo,read:org,gist",
	})
}

// verificationBase is the public base URL the device-flow verification_uri is built from:
// the configured ExternalURL when set (required behind a TLS-terminating front), otherwise
// derived from the request — correct when the proxy is served directly.
func (h *Handler) verificationBase(r *http.Request) string {
	if h.ExternalURL != "" {
		return strings.TrimRight(h.ExternalURL, "/")
	}
	return "https://" + r.Host
}

func (h *Handler) authorizePageDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(authorizePage)
}

// authorizePageWeb handles gh's browser (web) flow: record the grant keyed by gh's state +
// callback, then serve the same authorize page (it reads state from the URL).
func (h *Handler) authorizePageWeb(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")
	if state == "" || redirectURI == "" {
		http.Error(w, "missing state or redirect_uri", http.StatusBadRequest)
		return
	}
	g := &grant{flow: "web", state: state, redirectURI: redirectURI, userCode: randUserCode(), status: statusPending}
	h.grants.add(g)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(authorizePage)
}

// --- authorize page AJAX -----------------------------------------------------------------

type beginReq struct {
	UserCode string `json:"user_code"`
	State    string `json:"state"`
}

// apiBegin looks up the grant the operator is authorizing and starts the inner GitHub device
// flow, returning the GitHub code/URL for the page to display.
func (h *Handler) apiBegin(w http.ResponseWriter, r *http.Request) {
	var req beginReq
	if !readJSON(w, r, &req) {
		return
	}
	match := byUserCode(strings.ToUpper(strings.TrimSpace(req.UserCode)))
	if req.State != "" {
		match = byState(req.State)
	}

	var id, userCode string
	var started bool
	found := h.grants.withGrant(match, func(g *grant) {
		id, userCode, started = g.id, g.userCode, g.ghDeviceCode != ""
	})
	if !found {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "unknown or expired code"})
		return
	}
	if started {
		// idempotent on page reload: we can't recover GitHub's user_code from the device_code,
		// so tell the page it's already in progress and to keep polling.
		jsonResp(w, http.StatusOK, map[string]any{"grant_id": id, "user_code": userCode, "in_progress": true})
		return
	}

	da, err := oauth.RequestDeviceCode(r.Context(), oauth.Config{
		ClientID: h.OAuthClientID, Scopes: h.OAuthScopes, BaseURL: h.GitHubBaseURL, Client: h.HTTPClient,
	})
	if err != nil {
		jsonResp(w, http.StatusBadGateway, map[string]string{"error": "could not start GitHub login: " + err.Error()})
		return
	}
	var interval int
	h.grants.withGrant(byID(id), func(g *grant) {
		if g.ghDeviceCode == "" {
			g.ghDeviceCode, g.ghInterval = da.DeviceCode, da.Interval
		}
		interval = g.ghInterval
	})
	jsonResp(w, http.StatusOK, map[string]any{
		"grant_id":            id,
		"user_code":           userCode,
		"github_user_code":    da.UserCode,
		"github_verification": da.VerificationURI,
		"interval":            interval,
	})
}

// apiPoll polls the inner GitHub device flow once; on success it verifies the GitHub login is
// the custodian owner (the identity gate) and marks the grant authenticated or denied.
func (h *Handler) apiPoll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GrantID string `json:"grant_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var ghDeviceCode, login string
	var st grantStatus
	found := h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		ghDeviceCode, st, login = g.ghDeviceCode, g.status, g.login
	})
	if !found {
		jsonResp(w, http.StatusNotFound, map[string]string{"status": "expired"})
		return
	}
	switch st {
	case statusAuthenticated, statusApproved:
		jsonResp(w, http.StatusOK, map[string]string{"status": "authenticated", "login": login})
		return
	case statusDenied:
		jsonResp(w, http.StatusOK, map[string]string{"status": "denied", "error": "GitHub login is not the proxy's custodian owner"})
		return
	}
	if ghDeviceCode == "" {
		jsonResp(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	}

	tok, status, err := oauth.Poll(r.Context(), oauth.Config{
		ClientID: h.OAuthClientID, BaseURL: h.GitHubBaseURL, Client: h.HTTPClient,
	}, ghDeviceCode)
	if err != nil {
		jsonResp(w, http.StatusOK, map[string]string{"status": "pending"}) // transient; keep polling
		return
	}
	switch status {
	case oauth.PollPending, oauth.PollSlowDown:
		jsonResp(w, http.StatusOK, map[string]string{"status": "pending"})
		return
	case oauth.PollDenied, oauth.PollExpired:
		h.grants.withGrant(byID(req.GrantID), func(g *grant) { g.status = statusDenied })
		jsonResp(w, http.StatusOK, map[string]string{"status": "denied", "error": "GitHub authorization was declined or expired"})
		return
	}

	// Authorized by GitHub — now the identity gate: the login MUST be the custodian owner.
	who, err := h.resolveLogin(r.Context(), tok)
	if err != nil {
		jsonResp(w, http.StatusBadGateway, map[string]string{"status": "error", "error": "could not read GitHub identity"})
		return
	}
	owner, err := h.ownerLogin(r.Context())
	if err != nil {
		jsonResp(w, http.StatusBadGateway, map[string]string{"status": "error", "error": "could not resolve custodian owner"})
		return
	}
	if !strings.EqualFold(who, owner) {
		h.grants.withGrant(byID(req.GrantID), func(g *grant) { g.status = statusDenied })
		jsonResp(w, http.StatusOK, map[string]string{"status": "denied",
			"error": fmt.Sprintf("%q is not authorized; only the custodian owner (%q) may mint tokens", who, owner)})
		return
	}
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		if g.status == statusPending {
			g.status, g.login = statusAuthenticated, who
		}
	})
	jsonResp(w, http.StatusOK, map[string]string{"status": "authenticated", "login": who})
}

type approveReq struct {
	GrantID string        `json:"grant_id"`
	Name    string        `json:"name"`
	Policy  policy.Policy `json:"policy"`
}

// apiApprove mints the scoped proxy token for an authenticated grant and records the secret
// (device) or an auth code + redirect (web) for gh to collect.
func (h *Handler) apiApprove(w http.ResponseWriter, r *http.Request) {
	var req approveReq
	if !readJSON(w, r, &req) {
		return
	}
	// Reserve the grant for minting (only from the authenticated state) so a double-submit
	// can't mint twice.
	var ok bool
	var login, flow, redirectURI, state string
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		if g.status == statusAuthenticated {
			g.status = statusApproved // provisional; secret filled in below
			ok, login, flow, redirectURI, state = true, g.login, g.flow, g.redirectURI, g.state
		}
	})
	if !ok {
		jsonResp(w, http.StatusConflict, map[string]string{"error": "grant is not authenticated (authorize with GitHub first)"})
		return
	}

	pol := req.Policy
	ensureLoginUsable(&pol)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "ghlogin-" + login
	}
	_, secret, err := h.Store.Create(name, pol)
	if err != nil {
		h.grants.withGrant(byID(req.GrantID), func(g *grant) { g.status = statusAuthenticated }) // revert
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not mint token"})
		return
	}

	var authCode string
	if flow == "web" {
		authCode = randHex(32)
	}
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		g.secret, g.authCode = secret, authCode
	})

	if flow == "web" {
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		jsonResp(w, http.StatusOK, map[string]string{
			"status":   "approved",
			"redirect": redirectURI + sep + "code=" + authCode + "&state=" + state,
		})
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "approved"})
}

// --- identity --------------------------------------------------------------------------

// ownerLogin resolves and caches the custodian token's GitHub login — the only identity
// allowed to authorize a token mint. A failure is not cached, so it is retried next time.
func (h *Handler) ownerLogin(ctx context.Context) (string, error) {
	h.ownerMu.Lock()
	defer h.ownerMu.Unlock()
	if h.owner != "" {
		return h.owner, nil
	}
	who, err := h.resolveLogin(ctx, h.UpstreamToken)
	if err != nil {
		return "", err
	}
	if who == "" {
		return "", fmt.Errorf("custodian token returned an empty login")
	}
	h.owner = who
	return who, nil
}

// resolveLogin returns viewer{login} for a token via GitHub's GraphQL API.
func (h *Handler) resolveLogin(ctx context.Context, token string) (string, error) {
	body, _ := json.Marshal(map[string]string{"query": "{viewer{login}}"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.APIBaseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bgh-proxy")
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	var parsed struct {
		Data struct {
			Viewer struct {
				Login string `json:"login"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	return parsed.Data.Viewer.Login, nil
}

// ensureLoginUsable guarantees the minted token can complete gh's post-login checks: gh runs
// {viewer{login}} (unscoped "user") right after login, and the GHE handshake reads "meta". A
// token denied those can never finish `gh auth login`, so we raise them to at least read.
func ensureLoginUsable(p *policy.Policy) {
	if p.Defaults.Unscoped == nil {
		p.Defaults.Unscoped = map[string]policy.Access{}
	}
	for _, cat := range []string{"user", "meta"} {
		if p.Defaults.Unscoped[cat] < policy.AccessRead {
			p.Defaults.Unscoped[cat] = policy.AccessRead
		}
	}
}

// --- helpers ---------------------------------------------------------------------------

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return false
	}
	return true
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
