package restfilter

import (
	"bytes"
	"encoding/json"
)

// Denied-content scrub (hand-maintained — round-21).
//
// A few WRITE responses embed, under a single field, a FULL content object from ANOTHER repository the
// client referenced by node id — the projectsV2 add-item/add-draft endpoints, whose `content` is the
// issue / pull-request (with title+body) the client linked. The custodian (broad token) can read it even
// when the proxy client's policy denies that repo, so the response is a REST sidedoor around the
// node(id:) content-read block: a client with project write but no access to a private repo could read
// its issue/PR content by adding it to a project. The proxy NULLS the `content` field when it carries a
// denied repository.
//
// This is null-on-DENIED (not fail-closed like the cross-ref Scrub): a legitimately repo-less item (a
// draft issue) carries no repository, so it must be KEPT — failing it closed would drop the client's own
// draft.
var contentRepoScrubOps = map[string][]string{
	"/orgs/{org}/projectsV2/{project_number}/drafts":      {"content"},
	"/orgs/{org}/projectsV2/{project_number}/items":       {"content"},
	"/user/{user_id}/projectsV2/{project_number}/drafts":  {"content"},
	"/users/{username}/projectsV2/{project_number}/items": {"content"},
	// The single-item GET + PATCH twins (`/items/{item_id}`) carry the SAME `content` (the linked Issue/PR of
	// a possibly-denied repo) but were omitted, so a PATCH updating a board item streamed the denied repo's
	// title/body/repository on the write path (which runs only Write/Content scrub, no Pass body-scan) —
	// round-44 Finding 2. The op's `content` is an opaque additionalProperties body the spec-derived RepoReach
	// cannot see, so TestSpecCoverage_ProjectItemContentScrubbed enumerates these project-item paths explicitly.
	"/orgs/{org}/projectsV2/{project_number}/items/{item_id}":       {"content"},
	"/users/{username}/projectsV2/{project_number}/items/{item_id}": {"content"},
	// The per-VIEW item lists carry the same linked `content` (one element per board item) — round-44 F2.
	"/orgs/{org}/projectsV2/{project_number}/views/{view_number}/items":       {"content"},
	"/users/{username}/projectsV2/{project_number}/views/{view_number}/items": {"content"},
	// A CodeQL variant-analysis (POST) echoes its target repos in scanned_repositories[].repository and
	// skipped_repositories.*; the classifier scopes the `repositories[]`/`repository_owners[]` body forms,
	// but the `repository_lists` form names a saved list the proxy can't resolve offline, so null these
	// fields wholesale if any names a denied repo — closing the identity oracle for every target form
	// (round-23). The per-repo RESULTS are fetched via a path-scoped GET, gated separately.
	"/repos/{owner}/{repo}/code-scanning/codeql/variant-analyses": {"scanned_repositories", "skipped_repositories"},
	// Codespace WRITE responses (create/update/start/stop) echo `repository` — the repo the codespace is
	// for, a DIFFERENT repo than the unscoped /user/codespaces path. The GET forms are NeedsFilter-
	// redacted, but the write path is not, so a token with `user` write + a per-repo `none` carve-out
	// could read the denied repo's metadata via its own codespace (round-21). Null `repository` when denied.
	"/user/codespaces":                                                 {"repository"},
	"/user/codespaces/{codespace_name}":                                {"repository"},
	"/user/codespaces/{codespace_name}/start":                          {"repository"},
	"/user/codespaces/{codespace_name}/stop":                           {"repository"},
	"/orgs/{org}/members/{username}/codespaces/{codespace_name}/start": {"repository"},
	"/orgs/{org}/members/{username}/codespaces/{codespace_name}/stop":  {"repository"},
}

type contentScrubTemplate struct {
	tmpl   opTemplate
	fields []string
}

var contentScrubTemplates []contentScrubTemplate

func init() {
	for key, fields := range contentRepoScrubOps {
		contentScrubTemplates = append(contentScrubTemplates, contentScrubTemplate{tmpl: parseTemplate(key, nil), fields: fields})
	}
}

// ContentScrubFields returns the top-level response fields to null-if-denied for normPath, or nil.
func ContentScrubFields(normPath string) []string {
	ps := segments(normPath)
	for _, t := range contentScrubTemplates {
		if t.tmpl.matches(ps) {
			return t.fields
		}
	}
	return nil
}

// ScrubDeniedContent nulls each named top-level field of the response object that CONTAINS a denied
// repository (by any full_name / repository_url / minimal-repo identity); a field with no repository (a
// draft) or only allowed repositories is kept. It FAILS CLOSED (ok=false) on a non-empty body it cannot
// parse, like Redact; an empty body passes through. authorized receives "owner/repo".
func ScrubDeniedContent(body []byte, fields []string, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	scrubContentRoots(root, fields, authorized)
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

// scrubContentRoots nulls each named field of every OBJECT at the top level of the response — whether the
// response is a single object OR an ARRAY of objects. A projectsV2 `.../items` LIST returns a JSON array,
// which the object-only descent silently skipped, leaking the denied repo's linked Issue/PR content — and
// because the op is registered in contentRepoScrubOps the Pass body-scan backstop never ran (round-36). It
// descends array nesting but NOT an object's own children (the scrub fields are top-level on each item).
func scrubContentRoots(v any, fields []string, authorized func(string) bool) {
	switch t := v.(type) {
	case map[string]any:
		for _, f := range fields {
			if val, present := t[f]; present && val != nil {
				if denied, _ := scanMarkedRepos(val, authorized); denied {
					t[f] = nil
				}
			}
		}
	case []any:
		for _, el := range t {
			scrubContentRoots(el, fields, authorized)
		}
	}
}
