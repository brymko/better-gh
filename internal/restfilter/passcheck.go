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
func ContainsDeniedRepo(body []byte, authorized func(ownerRepo string) bool) (denied, parsedOK bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return false, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return false, false
	}
	return scanForDeniedRepo(root, authorized), true
}

func scanForDeniedRepo(v any, authorized func(string) bool) bool {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["full_name"].(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
			return true
		}
		if u, ok := t["repository_url"].(string); ok {
			if r := repoFromAPIURL(u); r != "" && !authorized(r) {
				return true
			}
		}
		// minimal {id,name,url} event/timeline repo shape: name == "owner/repo".
		if isMinimalRepoObject(t) {
			if s, ok := t["name"].(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
				return true
			}
		}
		for _, child := range t {
			if scanForDeniedRepo(child, authorized) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if scanForDeniedRepo(child, authorized) {
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
