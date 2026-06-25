// Package npm proxies GitHub's npm package registry (npm.pkg.github.com) alongside the
// GitHub API. GitHub Packages npm is SCOPED-ONLY — every request path is under an `@scope`
// segment (packument / publish), the npm utility namespace `/-/`, or a `/download/` tarball —
// none of which exist in the GitHub REST/GraphQL path space, so the same proxy host can serve
// both and route by path with no ambiguity (a misrouted path 404s, it cannot leak). The scope
// owner (a user or org login) is authorized exactly like an org `packages` grant, and the
// packument response is scrubbed: tarball URLs are rewritten back through the proxy so
// downloads are policy-checked too, and the package's repository cross-reference is nulled when
// the policy denies reading the backing repository — the same repo-level filtering the API
// paths apply.
package npm

import (
	"bytes"
	"encoding/json"
	"strings"
)

// DefaultUpstream is GitHub's npm registry, the upstream when no override is configured.
const DefaultUpstream = "https://npm.pkg.github.com"

const registryBase = "https://npm.pkg.github.com"

// IsRegistryPath reports whether a normalized request path targets the npm registry rather
// than the GitHub API. The discriminators are npm-only: an `@scope` segment, the `/-/` utility
// namespace, and `/download/` tarballs. The GitHub API never uses any of these (its owners are
// bare logins with no `@`), so this never reclassifies an API request.
func IsRegistryPath(norm string) bool {
	for _, seg := range splitPath(norm) {
		if strings.HasPrefix(seg, "@") {
			return true
		}
	}
	return strings.HasPrefix(norm, "/-/") || strings.HasPrefix(norm, "/download/")
}

// Owner returns the scope owner (user or org login) named by an npm registry path and whether
// one was present. The scope is the first `@`-prefixed segment with the `@` stripped, covering
// `/@owner/name`, `/download/@owner/name/...`, and `/-/package/@owner%2fname/...`. A path that
// names no scope (`/-/whoami`, `/-/ping`) returns ok=false so the caller can fail closed — it
// cannot be policy-gated, and `/-/whoami` would otherwise echo the custodian's identity.
func Owner(norm string) (owner string, ok bool) {
	for _, seg := range splitPath(norm) {
		if !strings.HasPrefix(seg, "@") {
			continue
		}
		owner = seg[1:]
		// A %2f-encoded scope (`@owner%2fname`) survives as one segment when the slash was not
		// decoded; cut at the earliest slash, whatever its form, to isolate the owner.
		for _, sep := range []string{"/", "%2f", "%2F"} {
			if i := strings.Index(owner, sep); i >= 0 {
				owner = owner[:i]
			}
		}
		if owner == "" {
			return "", false
		}
		return owner, true
	}
	return "", false
}

// IsPackument reports whether a GET path is a packument (the JSON metadata document for a
// package), as opposed to a tarball or utility endpoint. Only packuments are JSON-scrubbed; a
// tarball (`/download/...` or `/@owner/name/-/...tgz`) is a binary stream that forwards
// untouched. The packument shape is `/@owner/name` or the `%2f`-encoded `/@owner%2fname`.
func IsPackument(norm string) bool {
	segs := splitPath(norm)
	if len(segs) == 0 || !strings.HasPrefix(segs[0], "@") {
		return false
	}
	for _, s := range segs {
		if s == "-" {
			return false // /@owner/name/-/...tgz is the canonical npm tarball form
		}
	}
	return len(segs) <= 2
}

// ScrubPackument filters an npm packument before it reaches the client. It (1) rewrites every
// tarball URL that points at the npm registry to the proxy host, so tarball downloads route back
// through the proxy and are policy-checked, and (2) nulls the package's repository/bugs/homepage
// cross-references when canReadRepo reports the backing GitHub repository is denied — mirroring
// the REST/GraphQL repo redaction. repoFromWebURL maps a `github.com/owner/repo` web URL to
// `owner/repo` (and "" for non-GitHub hosts, which are left untouched). It FAILS CLOSED: an
// unparseable body returns ok=false and the caller must not forward the bytes.
func ScrubPackument(body []byte, proxyHost string, canReadRepo func(repo string) bool, repoFromWebURL func(string) string) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	// UseNumber so large integers / version-adjacent numbers round-trip as their exact source
	// literal rather than through float64 (lossy) — the scrub never interprets numbers.
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}

	repoOfURL := func(u string) string {
		// Drop a URL fragment/query (e.g. homepage `…/repo#readme`, bugs `…/repo/issues?x=1`) so the
		// repo segment isn't mistaken for `repo#readme` and slip past the denied-repo match.
		if i := strings.IndexAny(u, "#?"); i >= 0 {
			u = u[:i]
		}
		if r := repoFromWebURL(u); r != "" {
			return r
		}
		// scp-like remote (`git@github.com:owner/repo.git`) has no `://` for repoFromWebURL.
		const scp = "git@github.com:"
		if strings.HasPrefix(u, scp) {
			p := strings.TrimSuffix(strings.TrimPrefix(u, scp), ".git")
			if parts := strings.SplitN(p, "/", 2); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				return parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
			}
		}
		return ""
	}
	repoOf := func(v any) string {
		switch t := v.(type) {
		case string:
			return repoOfURL(t)
		case map[string]any:
			if u, ok := t["url"].(string); ok {
				return repoOfURL(u)
			}
		}
		return ""
	}
	deniedRepo := func(v any) bool {
		r := repoOf(v)
		return r != "" && !canReadRepo(r)
	}

	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				switch k {
				case "repository", "bugs":
					if deniedRepo(child) {
						t[k] = nil
						continue
					}
				case "homepage":
					if deniedRepo(child) {
						t[k] = ""
						continue
					}
				}
				t[k] = walk(child)
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case string:
			return rewriteRegistryURL(t, proxyHost)
		default:
			return v
		}
	}
	doc = walk(doc)

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

// rewriteRegistryURL points an absolute npm-registry URL (e.g. an absolute dist.tarball) at the
// proxy host so the download is fetched through the proxy. Relative `/download/...` URLs already
// resolve against the registry base the client configured (the proxy), so they need no rewrite.
func rewriteRegistryURL(s, proxyHost string) string {
	if proxyHost != "" && strings.HasPrefix(s, registryBase) {
		return "https://" + proxyHost + s[len(registryBase):]
	}
	return s
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
