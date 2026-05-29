package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/auth"
	"better-gh/internal/classifier"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

type ListenerMode int

const (
	SocketMode ListenerMode = iota
	GHEMode
)

func (m ListenerMode) String() string {
	if m == GHEMode {
		return "ghe"
	}
	return "socket"
}

type Handler struct {
	GithubToken   string
	Store         *store.Store
	Audit         *audit.Logger
	AdminSecret   string
	Client        *http.Client
	Mode          ListenerMode
	SocketPolicy  *policy.Policy // used for socket mode when no proxy token matches
	NodeCache     *nodecache.Cache
	UpstreamURL   string // default "" → "https://api.github.com"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := r.URL.Path

	authHeader := r.Header.Get("Authorization")
	clientToken := auth.ExtractToken(authHeader)

	if h.Mode == GHEMode && clientToken == "" {
		jsonError(w, http.StatusUnauthorized, "bgh: unauthorized")
		return
	}

	proxyToken := h.Store.Lookup(clientToken)
	if h.Mode == GHEMode && proxyToken == nil {
		jsonError(w, http.StatusUnauthorized, "bgh: unauthorized")
		return
	}

	// Socket mode: if no proxy token matches, fall back to SocketPolicy
	// (gh sends its own GitHub token which won't be in the proxy store)

	if h.Mode == GHEMode && classifier.IsGHEAuthEndpoint(r.Method, path) {
		norm := classifier.NormalizePath(path)
		if norm == "/" || norm == "" {
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}
		h.forward(w, r, start, norm, nil, proxyToken, nil)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bgh: failed to read request body")
		return
	}

	classified := classifier.Classify(r.Method, path, body)

	if h.NodeCache != nil && !classified.HasRepo() && classified.Org == "" &&
		classified.Access == classifier.Write {
		norm := classifier.NormalizePath(path)
		if norm == "/graphql" || norm == "/graphql/" {
			if owner, repo, ok := h.NodeCache.Lookup(body); ok {
				classified.Owner = owner
				classified.Repo = repo
			}
		}
	}

	repoName := classified.RepoFullName()
	org := classified.EffectiveOrg()

	tokenName := ""
	var pol *policy.Policy

	if proxyToken != nil {
		tokenName = proxyToken.Name
		pol = &proxyToken.Policy
	} else if h.Mode == SocketMode && h.SocketPolicy != nil {
		tokenName = "(socket)"
		pol = h.SocketPolicy
	} else {
		durationMs := time.Since(start).Milliseconds()
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             path,
			Repo:             repoName,
			Resource:         classified.Resource,
			UnscopedCategory: classified.UnscopedCategory,
			Access:           classified.Access.String(),
			PolicyResult:     "denied: no token provided",
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
		})
		jsonError(w, http.StatusForbidden, "bgh: denied — no token provided")
		return
	}

	result := pol.Evaluate(repoName, org, classified.Access, classified.Resource, classified.UnscopedCategory)

	if !result.Allowed {
		durationMs := time.Since(start).Milliseconds()
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             path,
			Repo:             repoName,
			Resource:         classified.Resource,
			UnscopedCategory: classified.UnscopedCategory,
			Access:           classified.Access.String(),
			PolicyResult:     "denied: " + result.Reason,
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
			TokenName:        tokenName,
		})
		jsonError(w, http.StatusForbidden, fmt.Sprintf("bgh: denied — %s", result.Reason))
		return
	}

	if proxyToken != nil {
		go h.Store.TouchLastUsed(proxyToken.ID)
	}

	norm := classifier.NormalizePath(path)
	h.forward(w, r, start, norm, body, proxyToken, &classified)
}

func (h *Handler) upstreamBase() string {
	if h.UpstreamURL != "" {
		return h.UpstreamURL
	}
	return "https://api.github.com"
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, start time.Time, normPath string, body []byte, tok *store.ProxyToken, classified *classifier.Result) {
	base := h.upstreamBase()
	upstream := base + normPath
	if normPath == "/graphql" || normPath == "/graphql/" {
		upstream = base + "/graphql"
	}

	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = io.NopCloser(byteReader(body))
	} else if r.Body != nil && body == nil {
		bodyReader = r.Body
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, bodyReader)
	if err != nil {
		slog.Error("creating upstream request", "err", err)
		jsonError(w, http.StatusBadGateway, "bgh: internal error")
		return
	}

	req.Header.Set("Authorization", "token "+h.GithubToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "bgh-proxy/0.1")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	tokenName := ""
	if tok != nil {
		tokenName = tok.Name
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		durationMs := time.Since(start).Milliseconds()
		errAuditAccess := "read"
		errAuditRepo := ""
		errAuditResource := ""
		errAuditUnscopedCategory := ""
		if classified != nil {
			errAuditAccess = classified.Access.String()
			errAuditRepo = classified.RepoFullName()
			errAuditResource = classified.Resource
			errAuditUnscopedCategory = classified.UnscopedCategory
		}
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             r.URL.Path,
			Repo:             errAuditRepo,
			Resource:         errAuditResource,
			UnscopedCategory: errAuditUnscopedCategory,
			Access:           errAuditAccess,
			PolicyResult:     "allowed",
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
			TokenName:        tokenName,
		})
		slog.Error("upstream request failed", "err", err)
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("bgh: upstream error — %v", err))
		return
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	durationMs := time.Since(start).Milliseconds()

	auditAccess := "read"
	auditRepo := ""
	auditResource := ""
	auditUnscopedCategory := ""
	if classified != nil {
		auditAccess = classified.Access.String()
		auditRepo = classified.RepoFullName()
		auditResource = classified.Resource
		auditUnscopedCategory = classified.UnscopedCategory
	}

	h.Audit.Log(audit.Entry{
		Timestamp:        time.Now(),
		Method:           r.Method,
		Path:             r.URL.Path,
		Repo:             auditRepo,
		Resource:         auditResource,
		UnscopedCategory: auditUnscopedCategory,
		Access:           auditAccess,
		PolicyResult:     "allowed",
		GitHubStatus:     &status,
		DurationMs:       durationMs,
		Mode:             h.Mode.String(),
		TokenName:        tokenName,
	})

	for key, vals := range resp.Header {
		if key == "Transfer-Encoding" || key == "Content-Encoding" {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	isGraphQL := normPath == "/graphql" || normPath == "/graphql/"
	shouldIngest := h.NodeCache != nil && isGraphQL && classified != nil && classified.HasRepo()

	if shouldIngest {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		h.NodeCache.Ingest(classified.Owner, classified.Repo, respBody)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
	} else {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

type byteReaderWrapper struct {
	data []byte
	pos  int
}

func byteReader(b []byte) *byteReaderWrapper {
	return &byteReaderWrapper{data: b}
}

func (r *byteReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
