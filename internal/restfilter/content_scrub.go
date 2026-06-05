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
	if m, ok := root.(map[string]any); ok {
		for _, f := range fields {
			if v, present := m[f]; present && v != nil {
				if denied, _ := scanMarkedRepos(v, authorized); denied {
					m[f] = nil
				}
			}
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}
