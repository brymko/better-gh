package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"better-gh/internal/classifier"
	"better-gh/internal/policy"
	"better-gh/internal/restfilter"
)

// visEntry caches one repository's visibility. public is meaningful only for a confirmed
// lookup (failures are not cached, so a transient error does not stick).
type visEntry struct {
	public  bool
	expires time.Time
}

// visCache memoizes repo visibility (public/private) looked up from GitHub so the public-repo
// baseline (defaults.public) does not issue an upstream GET per request for the same repo.
// TTL-bounded (a repo can flip public↔private) with a crude size cap (cleared on overflow) so
// a client cannot grow it without bound by probing many repo names.
type visCache struct {
	mu     sync.Mutex
	m      map[string]visEntry
	ttl    time.Duration
	maxLen int
}

func newVisCache(ttl time.Duration) *visCache {
	return &visCache{m: map[string]visEntry{}, ttl: ttl, maxLen: 8192}
}

func (c *visCache) get(key string) (public, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.m[key]
	if !found || time.Now().After(e.expires) {
		if found {
			delete(c.m, key)
		}
		return false, false
	}
	return e.public, true
}

func (c *visCache) put(key string, public bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.maxLen {
		c.m = map[string]visEntry{} // bound memory; the next requests re-populate
	}
	c.m[key] = visEntry{public: public, expires: time.Now().Add(c.ttl)}
}

// repoIsPublic reports whether owner/repo is a PUBLIC repository per GitHub, looked up with the
// custodian token. The public-repo baseline uses it to decide whether an unlisted repo may be
// read WITHOUT ever fetching a private repo's contents for the client. Returns known=false on
// any failure (missing client/cache config, network error, non-200 — e.g. a private repo the
// custodian cannot see returns 404), and the caller then denies. The looked-up metadata never
// reaches the client; only the public/private bit is used.
func (h *Handler) repoIsPublic(ctx context.Context, owner, repo string) (public, known bool) {
	if owner == "" || repo == "" || h.Client == nil {
		return false, false
	}
	h.visOnce.Do(func() {
		if h.visibility == nil {
			h.visibility = newVisCache(10 * time.Minute)
		}
	})
	key := strings.ToLower(owner + "/" + repo)
	if pub, ok := h.visibility.get(key); ok {
		return pub, true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.upstreamBase()+"/repos/"+owner+"/"+repo, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Authorization", "token "+h.custodianToken())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "bgh-proxy/0.1")

	resp, err := h.Client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, false
	}
	var meta struct {
		Private    bool   `json:"private"`
		Visibility string `json:"visibility"`
		FullName   string `json:"full_name"`
	}
	if json.Unmarshal(body, &meta) != nil {
		return false, false
	}
	// Confirm the response is for the repo we asked about — guards against a redirect/rename
	// returning a DIFFERENT repo's visibility that we'd then attribute to owner/repo.
	if !strings.EqualFold(meta.FullName, owner+"/"+repo) {
		return false, false
	}
	// "internal" (enterprise org-wide) is NOT public; only visibility=="public" (or, on hosts
	// that omit the field, !private) counts as public.
	public = meta.Visibility == "public" || (meta.Visibility == "" && !meta.Private)
	h.visibility.put(key, public)
	return public, true
}

// allowPublicRead applies the public-repo baseline (defaults.public) to a READ that the
// explicit policy denied. The response filters keep only public, eligible repos, so for
// FILTERED paths — GraphQL (gqlfilter) and REST enumeration (restfilter) — it lets the request
// proceed and the filter redacts everything not public-and-eligible. For an UNFILTERED REST
// repo-scoped read (GET /repos/o/r/...), it authoritatively looks up the target repo's
// visibility and allows only a public, eligible repo, so a private repo is never fetched for
// the client. The caller still applies the fail-closed checks afterward (e.g. an untypeable
// GraphQL query has no response filter and is re-denied).
func (h *Handler) allowPublicRead(ctx context.Context, pol *policy.Policy, c *classifier.Result, norm string, denied policy.Result) policy.Result {
	if c.Access != classifier.Read || pol.Defaults.Public == policy.AccessNone {
		return denied
	}
	if norm == "/graphql" || norm == "/graphql/" || restfilter.IsRepoEnumPath(norm) {
		return policy.Result{Allowed: true}
	}
	if c.HasRepo() && pol.PublicReadEligible(c.RepoFullName(), c.Owner, classifier.Read) {
		if public, ok := h.repoIsPublic(ctx, c.Owner, c.Repo); ok && public {
			return policy.Result{Allowed: true}
		}
	}
	return denied
}
