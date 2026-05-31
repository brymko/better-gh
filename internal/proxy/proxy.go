package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
	GithubToken  string
	Store        *store.Store
	Audit        *audit.Logger
	Client       *http.Client
	Mode         ListenerMode
	SocketPolicy *policy.Policy // used for socket mode when no proxy token matches
	NodeCache    *nodecache.Cache
	UpstreamURL  string // default "" → "https://api.github.com"
}

const maxBodySize = 10 << 20 // 10 MB

// hopByHopOrManaged headers are not copied from the client to the upstream request:
// the client's Authorization is replaced with the real token, Host/Content-Length are
// recomputed, X-GitHub-Api-Version is pinned, and the rest are hop-by-hop.
var hopByHopOrManaged = map[string]bool{
	"Authorization":        true,
	"Host":                 true,
	"Content-Length":       true,
	"X-Github-Api-Version": true,
	"Connection":           true,
	"Proxy-Connection":     true,
	"Keep-Alive":           true,
	"Transfer-Encoding":    true,
	"Te":                   true,
	"Trailer":              true,
	"Upgrade":              true,
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
	}

	norm := classifier.NormalizePath(path)
	if h.Mode == GHEMode && (norm == "/user" || norm == "/user/") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"login":"bgh-proxy","id":0}`))
		return
	}

	if classifier.HasDotSegment(path) {
		jsonError(w, http.StatusBadRequest, "bgh: invalid path")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bgh: failed to read request body")
		return
	}

	classified := classifier.Classify(r.Method, path, body)

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
			Repo:             classified.RepoFullName(),
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

	// A request can address objects by opaque node ID with no repository() scope —
	// mutation inputs, and node(id:)/nodes(ids:) reads. Resolve every referenced node
	// ID to its REAL repository (authoritatively, via GitHub) and add those as scopes,
	// so a node-ID request cannot reach a repo the token can't access. Unresolvable
	// nodes fail closed. Gated on AllowsAny{Write,Read} so a token that can never act
	// at this access level cannot burn the upstream rate limit on doomed resolves.
	forceDenyReason := ""
	if h.NodeCache != nil && len(classified.NodeIDs) > 0 &&
		(norm == "/graphql" || norm == "/graphql/") {
		canResolve := pol.AllowsAnyWrite()
		if classified.Access == classifier.Read {
			canResolve = pol.AllowsAnyRead()
		}
		if !canResolve {
			forceDenyReason = "node-scoped request not permitted by policy"
		} else if scopes, ok := h.resolveNodeScopes(r.Context(), classified.NodeIDs); ok {
			if !classified.HasRepo() && classified.Org == "" {
				classified.Owner = scopes[0].Owner
				classified.Repo = scopes[0].Repo
				classified.Resource = scopes[0].Resource
				classified.Additional = append(classified.Additional, scopes[1:]...)
			} else {
				classified.Additional = append(classified.Additional, scopes...)
			}
		} else {
			forceDenyReason = "unresolved node id"
		}
	}

	repoName := classified.RepoFullName()

	result := evaluateScopes(pol, &classified)

	if forceDenyReason != "" || !result.Allowed {
		reason := forceDenyReason
		if reason == "" {
			reason = result.Reason
		}
		durationMs := time.Since(start).Milliseconds()
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             path,
			Repo:             repoName,
			Resource:         classified.Resource,
			UnscopedCategory: classified.UnscopedCategory,
			Access:           classified.Access.String(),
			PolicyResult:     "denied: " + reason,
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
			TokenName:        tokenName,
		})
		jsonError(w, http.StatusForbidden, "bgh: denied")
		return
	}

	if proxyToken != nil {
		go h.Store.TouchLastUsed(proxyToken.ID)
	}

	h.forward(w, r, start, norm, body, proxyToken, &classified)
}

// evaluateScopes allows a request only if EVERY scope it touches is allowed. A
// single GraphQL document may reference several repositories/orgs at once; checking
// only the primary scope would let a denied repo ride along (see classifier.Result).
func evaluateScopes(pol *policy.Policy, c *classifier.Result) policy.Result {
	for _, s := range c.AllScopes() {
		repo := ""
		if s.Owner != "" && s.Repo != "" {
			repo = s.Owner + "/" + s.Repo
		}
		org := s.Org
		if org == "" {
			org = s.Owner
		}
		if res := pol.Evaluate(repo, org, c.Access, s.Resource, s.UnscopedCategory); !res.Allowed {
			return res
		}
	}
	return policy.Result{Allowed: true}
}

// maxResolveIDs caps how many node IDs one mutation may reference. GitHub's
// nodes(ids:) accepts at most 100; beyond that the resolve would fail anyway, so we
// reject up front rather than build an oversized upstream query.
const maxResolveIDs = 100

// resolveNodeScopes maps each node ID to the repository GitHub says it belongs to.
// It returns one Scope per input ID (cache-first, then a single GitHub nodes(ids:)
// call for the misses) and ok=false if ANY node cannot be resolved — so an
// unresolvable or upstream-failed lookup fails closed.
func (h *Handler) resolveNodeScopes(ctx context.Context, ids []string) ([]classifier.Scope, bool) {
	if len(ids) > maxResolveIDs {
		return nil, false
	}
	resolved := make(map[string][2]string, len(ids))
	var missing []string
	for _, id := range ids {
		if owner, repo, ok := h.NodeCache.Get(id); ok {
			resolved[id] = [2]string{owner, repo}
		} else {
			missing = append(missing, id)
		}
	}

	if len(missing) > 0 {
		fetched, err := h.resolveFromGitHub(ctx, missing)
		if err != nil {
			slog.Error("node resolution failed", "err", err)
			return nil, false
		}
		for id, or := range fetched {
			h.NodeCache.Put(id, or[0], or[1])
			resolved[id] = or
		}
	}

	scopes := make([]classifier.Scope, 0, len(ids))
	for _, id := range ids {
		or, ok := resolved[id]
		if !ok {
			return nil, false // some node did not resolve → deny
		}
		scopes = append(scopes, classifier.Scope{Owner: or[0], Repo: or[1]})
	}
	return scopes, true
}

const resolveQuery = `query($ids:[ID!]!){nodes(ids:$ids){__typename ` +
	`... on RepositoryNode{repository{nameWithOwner}} ` +
	`... on Repository{nameWithOwner} ` +
	`... on Ref{repository{nameWithOwner}} ` +
	`... on Release{repository{nameWithOwner}}}}`

func (h *Handler) resolveFromGitHub(ctx context.Context, ids []string) (map[string][2]string, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"query":     resolveQuery,
		"variables": map[string]any{"ids": ids},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.upstreamBase()+"/graphql", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+h.GithubToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "bgh-proxy/0.1")

	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Data struct {
			Nodes []*struct {
				NameWithOwner string `json:"nameWithOwner"`
				Repository    *struct {
					NameWithOwner string `json:"nameWithOwner"`
				} `json:"repository"`
			} `json:"nodes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}

	out := make(map[string][2]string)
	// GitHub returns nodes in the same order as the input ids; null entries (no access
	// or wrong type) decode to a nil element and are left unresolved.
	for i, n := range parsed.Data.Nodes {
		if i >= len(ids) || n == nil {
			continue
		}
		nwo := n.NameWithOwner
		if n.Repository != nil && n.Repository.NameWithOwner != "" {
			nwo = n.Repository.NameWithOwner
		}
		if owner, repo, ok := splitNameWithOwner(nwo); ok {
			out[ids[i]] = [2]string{owner, repo}
		}
	}
	return out, nil
}

func splitNameWithOwner(nwo string) (owner, repo string, ok bool) {
	if i := strings.IndexByte(nwo, '/'); i > 0 && i < len(nwo)-1 {
		return nwo[:i], nwo[i+1:], true
	}
	return "", "", false
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

	// Forward the client's headers so media-type negotiation (raw/diff/patch/SARIF,
	// tarball/zipball) and conditional requests (ETag/Last-Modified) keep working. The
	// client's Authorization is dropped and replaced with the real token; hop-by-hop
	// and length/host headers are not forwarded.
	for k, vals := range r.Header {
		if hopByHopOrManaged[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Authorization", "token "+h.GithubToken)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "bgh-proxy/0.1")
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
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
		jsonError(w, http.StatusBadGateway, "bgh: upstream error")
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

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
