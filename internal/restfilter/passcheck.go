package restfilter

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ContainsDeniedRepo reports whether a JSON body surfaces any repository identity that `authorized`
// rejects. It is the defense-in-depth safety net for "Pass" responses — ones the static OpenAPI
// table (Lookup) believed carry NO repository, and which the proxy would otherwise forward
// unfiltered. The table can UNDER-detect a repo identity when GitHub's response schema is
// untyped/opaque/cyclic, so before forwarding a non-path-scoped Pass body the proxy scans the ACTUAL
// data and fails closed if a denied repo is present. It mirrors the generator's own repo-detection
// signals (internal/restfilter/gen): a `full_name` ("owner/repo") property, a `repository_url` API
// link, and the minimal {id,name,url} event-repo shape — so anything the generator WOULD have
// located is caught here too. Returns (containsDenied, parsedOK); a non-JSON body yields
// parsedOK=false, and the caller (having already gated on a JSON content-type) fails closed.
func ContainsDeniedRepo(body []byte, org string, authorized func(ownerRepo string) bool) (denied, parsedOK bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return false, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return false, false
	}
	return scanForDeniedRepo(root, org, authorized), true
}

func scanForDeniedRepo(v any, org string, authorized func(string) bool) bool {
	switch t := v.(type) {
	case string:
		// VALUE-driven catch for a github.com WEB url naming a repo (html_url / clone_url /
		// student_repository_url / …) — the shape the keyed checks miss (round-39 Classroom grades feed,
		// whose student_repository_url is a bare-repo html_url). Conservative: github.com host only, a
		// reserved-top-level-path denylist, so an ordinary github.com link does not over-fail the scan.
		if r := repoFromWebURL(t); r != "" && !authorized(r) {
			return true
		}
		return false
	case map[string]any:
		if s, ok := t["full_name"].(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
			return true
		}
		// repository_full_name: a full "owner/repo" property (org rulesets/properties feeds) — round-30.
		if s, ok := t["repository_full_name"].(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
			return true
		}
		if u, ok := t["repository_url"].(string); ok {
			if r := repoFromAPIURL(u); r != "" && !authorized(r) {
				return true
			}
		}
		// a bare `repository`/`repositoryName` STRING — "owner/repo" or a BARE repo name qualified by the
		// request's scoped org: org artifact storage/deployment records (`repository`, round-40) and the org
		// billing usage report (`repositoryName` camelCase — distinct from the snake_case repository_name
		// checked below, round-41). Only a string value is a name (a `repository` OBJECT is handled by the
		// recursion + full_name/url checks).
		for _, k := range [...]string{"repository", "repositoryName"} {
			if rep, ok := t[k].(string); ok && rep != "" {
				if strings.Count(rep, "/") == 1 && !authorized(rep) {
					return true
				}
				if !strings.Contains(rep, "/") && org != "" && !authorized(org+"/"+rep) {
					return true
				}
			}
		}
		// org-relative {repository_id, repository_name}: repository_name is a BARE repo name (no owner) on
		// the org rule-suites feed; qualify it with the request's scoped org before authorizing (round-30).
		if _, hasID := t["repository_id"]; hasID {
			if name, ok := t["repository_name"].(string); ok && name != "" {
				switch {
				case strings.Count(name, "/") == 1 && !authorized(name):
					return true
				case !strings.Contains(name, "/") && org != "" && !authorized(org+"/"+name):
					return true
				}
			}
		}
		// minimal {id,name,url} event/timeline repo shape: name == "owner/repo".
		if isMinimalRepoObject(t) {
			if s, ok := t["name"].(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
				return true
			}
		}
		for _, child := range t {
			if scanForDeniedRepo(child, org, authorized) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if scanForDeniedRepo(child, org, authorized) {
				return true
			}
		}
	}
	return false
}

// repoFromAPIURL extracts "owner/repo" from a GitHub API URL like
// https://api.github.com/repos/owner/repo[/...], or "" if it carries no /repos/{owner}/{repo}.
func repoFromAPIURL(u string) string {
	i := strings.Index(u, "/repos/")
	if i < 0 {
		return ""
	}
	parts := strings.SplitN(u[i+len("/repos/"):], "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// reservedWebFirstSegment are github.com top-level path segments that are NOT a repo owner, so a
// github.com/<seg>/… URL must not be mis-parsed as owner/repo by the value-driven Pass body-scan.
var reservedWebFirstSegment = map[string]bool{
	"orgs": true, "organizations": true, "users": true, "settings": true, "sponsors": true,
	"marketplace": true, "apps": true, "notifications": true, "new": true, "login": true,
	"join": true, "about": true, "pricing": true, "features": true, "topics": true,
	"collections": true, "trending": true, "events": true, "codespaces": true, "enterprises": true,
	"account": true, "dashboard": true, "search": true, "explore": true, "stars": true,
	"watching": true, "gist": true, "site": true, "contact": true, "security": true, "readme": true,
}

// repoFromWebURL extracts "owner/repo" from a GitHub WEB url (html_url / clone_url / *_repository_url),
// e.g. "https://github.com/owner/repo", ".../owner/repo/issues/1", or ".../owner/repo.git". Returns "" for a
// non-github.com host, a 1-segment profile url, or a reserved top-level path — the conservative form that
// avoids false-positives in the fail-closed Pass body-scan (round-39).
func repoFromWebURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return ""
	}
	if host := rest[:j]; host != "github.com" && host != "www.github.com" {
		return "" // EXACTLY github.com — excludes api.github.com (".../repos/owner/repo" API links, keyed-checked elsewhere) and GHE hosts
	}
	parts := strings.SplitN(rest[j+1:], "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" || reservedWebFirstSegment[parts[0]] {
		return ""
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return ""
	}
	return parts[0] + "/" + repo
}

// isMinimalRepoObject reports whether m is the inline {id,name,url} repository shape GitHub uses in
// event/timeline payloads (name = "owner/repo", no full_name) — mirroring the generator's
// isMinimalRepo so the scan recognizes the same shape. The id+url+small-object gate keeps it from
// matching a branch/file object whose `name` merely happens to contain a slash.
func isMinimalRepoObject(m map[string]any) bool {
	if _, ok := m["full_name"]; ok {
		return false
	}
	_, hasName := m["name"]
	_, hasURL := m["url"]
	_, hasID := m["id"]
	return hasName && hasURL && hasID && len(m) <= 4
}
