package restfilter

import (
	"bytes"
	"encoding/json"
	"strings"
)

// org-qualified bare-repo-NAME arrays (hand-maintained — see below).
//
// A few org/user-scoped GET ops return a repository array whose elements name the repo only by a BARE
// `name` (no owner, no full_name, no url) — the owner is the {org}/{username} PATH parameter. The
// canonical case is GitHub artifact attestations:
//
//	GET /orgs/{org}/attestations/repositories  →  [ { "id": <int>, "name": "<repo>" }, … ]
//
// The OpenAPI generator locates a repo only via a full_name property or the minimal {id,name,url}
// object shape, so a bare {id,name} is invisible to it (the op is Pass), and the ContainsDeniedRepo
// body-scan can't map it either — so a client holding the org at base=read but DENIED specific private
// repos in it enumerated those repos' NAMES/existence (round-20, same class as round-19 F4/F6). The
// proxy qualifies each name with the path owner and drops the denied ones.
//
// Maintenance: hand-maintained. Pass ops returning a bare {id,name} repo array (no full_name/url)
// qualified by a path {org}/{username} belong here.
var orgNamedRepoArrayOps = []string{
	"/orgs/{org}/attestations/repositories",
}

// nestedBareNameRepoOps return a DEEPLY-NESTED bare-`name` repository array (no full_name/id/url) the
// generator/body-scan cannot locate — the org Copilot metrics feeds, whose
// copilot_dotcom_pull_requests.repositories[] names a repo only by a bare `name` qualified by the path org.
// A client with the org at base=read but a per-repo `none` carve-out otherwise enumerated the denied
// private repo's NAME + Copilot usage (round-33, same class as attestations/repositories round-20).
// TestSpecCoverage_NestedBareNameRepos asserts this list equals the spec ops with that shape.
var nestedBareNameRepoOps = []string{
	"/orgs/{org}/copilot/metrics",
	"/orgs/{org}/team/{team_slug}/copilot/metrics",
}

var orgNamedRepoTemplates []opTemplate
var nestedBareNameRepoTemplates []opTemplate

func init() {
	for _, p := range orgNamedRepoArrayOps {
		orgNamedRepoTemplates = append(orgNamedRepoTemplates, parseTemplate(p, nil))
	}
	for _, p := range nestedBareNameRepoOps {
		nestedBareNameRepoTemplates = append(nestedBareNameRepoTemplates, parseTemplate(p, nil))
	}
}

// IsNestedBareNameRepoOp reports whether normPath returns a nested bare-`name` repository array qualified
// by the path org (segments[1]).
func IsNestedBareNameRepoOp(normPath string) bool {
	ps := segments(normPath)
	for _, t := range nestedBareNameRepoTemplates {
		if t.matches(ps) {
			return true
		}
	}
	return false
}

// RedactNestedBareNameRepos walks the response and, for every nested `repositories` array whose elements
// name a repo only by a bare `name` (no full_name/url), drops the ones whose owner/name the policy denies
// (owner = the path org). Fails closed on a non-empty unparseable body or a missing path owner. Other
// `repositories` shapes (full_name-bearing) are left to the full_name scan.
func RedactNestedBareNameRepos(body []byte, owner string, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	if owner == "" {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	redactBareNameReposWalk(root, owner, authorized)
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

func redactBareNameReposWalk(v any, owner string, authorized func(string) bool) {
	switch t := v.(type) {
	case map[string]any:
		if arr, ok := t["repositories"].([]any); ok && isBareNameRepoArray(arr) {
			t["repositories"] = filterNamedRepoArray(arr, owner, authorized)
		}
		for _, c := range t {
			redactBareNameReposWalk(c, owner, authorized)
		}
	case []any:
		for _, c := range t {
			redactBareNameReposWalk(c, owner, authorized)
		}
	}
}

// isBareNameRepoArray reports whether arr is a non-empty array of objects each naming a repo by a BARE
// `name` (no "/") with no full_name (so it is the bare-name shape, not a full-repository array).
func isBareNameRepoArray(arr []any) bool {
	if len(arr) == 0 {
		return false
	}
	for _, el := range arr {
		m, ok := el.(map[string]any)
		if !ok {
			return false
		}
		name, ok := m["name"].(string)
		if !ok || strings.Contains(name, "/") {
			return false
		}
		if _, hasFull := m["full_name"]; hasFull {
			return false
		}
	}
	return true
}

// IsOrgNamedRepoArray reports whether normPath returns a bare {id,name} repo array qualified by the
// path owner (segments[1]).
func IsOrgNamedRepoArray(normPath string) bool {
	ps := segments(normPath)
	for _, t := range orgNamedRepoTemplates {
		if t.matches(ps) {
			return true
		}
	}
	return false
}

// RedactOrgNamedRepos drops bare-name repo objects whose owner/name the policy denies. owner is the
// path owner (the {org}/{username} segment). It FAILS CLOSED (ok=false) on a non-empty body whose
// shape is not the expected repo-name array (a root array, or a single `repositories`/`attestations`
// array field of {id,name} objects): we KNOW this op carries repo names, so a shape we cannot redact
// must not be forwarded. An empty body passes through. authorized receives "owner/repo".
func RedactOrgNamedRepos(body []byte, owner string, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	if owner == "" {
		return nil, false // cannot qualify bare names without the path owner → fail closed
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	switch r := root.(type) {
	case []any:
		root = filterNamedRepoArray(r, owner, authorized)
	case map[string]any:
		// Defensive: if GitHub ever wraps the array in a single field, redact that one array field;
		// otherwise (no recognizable repo-name array) fail closed rather than forward unredacted.
		field, arr := singleNamedRepoArrayField(r)
		if arr == nil {
			return nil, false
		}
		r[field] = filterNamedRepoArray(arr, owner, authorized)
	default:
		return nil, false
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

// filterNamedRepoArray keeps only {…,"name":"<repo>"} elements whose owner/name is allowed. An element
// that is not an object, or exposes no string name, is dropped (fail closed — this op's elements are
// repositories).
func filterNamedRepoArray(arr []any, owner string, authorized func(string) bool) []any {
	kept := make([]any, 0, len(arr))
	for _, el := range arr {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		name, ok := m["name"].(string)
		if !ok || name == "" || strings.Contains(name, "/") {
			continue
		}
		if authorized(owner + "/" + name) {
			kept = append(kept, el)
		}
	}
	return kept
}

// singleNamedRepoArrayField returns the one field of m whose value is an array of {id,name} repo
// objects, or ("", nil) if there is not exactly one such field.
func singleNamedRepoArrayField(m map[string]any) (string, []any) {
	field, count := "", 0
	var found []any
	for k, v := range m {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		allNamed := true
		for _, el := range arr {
			o, ok := el.(map[string]any)
			if !ok {
				allNamed = false
				break
			}
			if _, ok := o["name"].(string); !ok {
				allNamed = false
				break
			}
		}
		if allNamed {
			field, found, count = k, arr, count+1
		}
	}
	if count != 1 {
		return "", nil
	}
	return field, found
}
