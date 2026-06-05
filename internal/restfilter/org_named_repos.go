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
// Maintenance: hand-maintained. When refreshing against a new spec, audit Pass ops returning a bare
// {id,name} repo array (no full_name/url) qualified by a path {org}/{username} and add them here.
var orgNamedRepoArrayOps = []string{
	"/orgs/{org}/attestations/repositories",
}

var orgNamedRepoTemplates []opTemplate

func init() {
	for _, p := range orgNamedRepoArrayOps {
		orgNamedRepoTemplates = append(orgNamedRepoTemplates, parseTemplate(p, nil))
	}
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
