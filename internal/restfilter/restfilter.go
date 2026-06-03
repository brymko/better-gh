// Package restfilter redacts denied-repo entries from REST enumeration/search responses.
//
// The GraphQL response filter (internal/gqlfilter) makes cross-repo navigation and
// enumeration safe for GraphQL, but the equivalent REST endpoints return the same data and
// are not GraphQL. Without this, a client granted the "user"/"search" categories could
// enumerate denied repositories' metadata via /user/repos or /orgs/{org}/repos, and read
// denied repositories' code/issues via /search/code, /search/issues, /user/issues — so the
// REST path would undo the isolation the GraphQL filter enforces. This filters the
// well-known repo-bearing list/search endpoints by dropping entries whose repository the
// policy denies. It is defense-in-depth (the fine-grained upstream PAT remains the floor):
// an unrecognized JSON shape is passed through unchanged rather than failing the request.
package restfilter

import (
	"encoding/json"
	"strings"
)

func segments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// IsRepoEnumPath reports whether normPath is a REST endpoint that returns repository-bearing
// entries from MORE than one repository (so its response must be redacted per repo). Single
// repo paths (/repos/{owner}/{repo}/...) are already scoped by the classifier and excluded.
func IsRepoEnumPath(normPath string) bool {
	s := segments(normPath)
	switch {
	case len(s) == 2 && s[0] == "user" && (s[1] == "repos" || s[1] == "starred" || s[1] == "subscriptions" || s[1] == "issues"):
		return true
	case len(s) == 3 && s[0] == "orgs" && (s[2] == "repos" || s[2] == "issues"):
		return true
	case len(s) == 3 && s[0] == "users" && s[2] == "repos":
		return true
	case len(s) == 4 && s[0] == "repos" && s[3] == "forks":
		// /repos/{owner}/{repo}/forks returns repository objects owned by OTHERS; the GraphQL
		// filter already redacts `forks`, so redact here too (the parent repo is policy-checked
		// by the classifier; denied forks are dropped by full_name).
		return true
	case len(s) == 1 && (s[0] == "repositories" || s[0] == "issues" || s[0] == "notifications"):
		return true
	case len(s) == 2 && s[0] == "search" && (s[1] == "repositories" || s[1] == "code" || s[1] == "issues" || s[1] == "commits"):
		return true
	}
	return false
}

// Filter redacts denied-repo entries from a recognized enumeration/search response.
// authorized receives "owner/repo" and the entry's visibility (isPrivate, with unknown
// reported as private so the public-repo baseline never keeps an entry whose visibility could
// not be determined). Repo-list / issue-list endpoints return a JSON array; search endpoints
// return {items:[...], total_count, ...}. An off-shape body (e.g. an error object) is returned
// unchanged.
func Filter(normPath string, body []byte, authorized func(ownerRepo string, isPrivate bool) bool) []byte {
	s := segments(normPath)
	if len(s) >= 1 && s[0] == "search" {
		return filterSearch(body, authorized)
	}
	return filterArray(body, authorized)
}

func filterArray(body []byte, authorized func(string, bool) bool) []byte {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) != nil {
		return body // not an array (error object / unexpected shape) → unchanged
	}
	kept := make([]json.RawMessage, 0, len(arr))
	for _, raw := range arr {
		if repoAllowed(raw, authorized) {
			kept = append(kept, raw)
		}
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return body
	}
	return out
}

func filterSearch(body []byte, authorized func(string, bool) bool) []byte {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return body
	}
	itemsRaw, ok := obj["items"]
	if !ok {
		return body // not a search-results object (e.g. an error) → unchanged
	}
	var items []json.RawMessage
	if json.Unmarshal(itemsRaw, &items) != nil {
		return body
	}
	kept := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		if repoAllowed(it, authorized) {
			kept = append(kept, it)
		}
	}
	nb, err := json.Marshal(kept)
	if err != nil {
		return body
	}
	obj["items"] = nb
	// If anything was dropped, total_count would otherwise be a denied-repo existence oracle
	// (e.g. /search/code?q="exact-secret" returns empty items but total_count=1, confirming
	// the secret exists in a repo the client can't read). Replace it with the kept count and
	// flag the response incomplete. (A query whose page had no denied matches keeps the true
	// count; a broad multi-page query may still leak an aggregate count on all-allowed pages.)
	if len(kept) < len(items) {
		if c, e := json.Marshal(len(kept)); e == nil {
			obj["total_count"] = c
		}
		obj["incomplete_results"] = json.RawMessage("true")
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// repoAllowed determines an entry's repository from the shapes these endpoints use — a
// repository object (full_name, or owner.login + name), a code/commit search item
// (repository.full_name), or an issue (repository.full_name or repository_url) — and reports
// whether the policy permits it. An entry whose repository cannot be determined is DROPPED
// (fail closed), since it cannot be proven to belong to an allowed repository.
func repoAllowed(raw json.RawMessage, authorized func(string, bool) bool) bool {
	var o struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
		Private  *bool  `json:"private"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
		Repository struct {
			FullName string `json:"full_name"`
			Private  *bool  `json:"private"`
		} `json:"repository"`
		RepositoryURL string `json:"repository_url"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return false
	}
	repo := o.FullName
	if repo == "" {
		repo = o.Repository.FullName
	}
	if repo == "" && o.Owner.Login != "" && o.Name != "" {
		repo = o.Owner.Login + "/" + o.Name
	}
	if repo == "" && o.RepositoryURL != "" {
		if i := strings.Index(o.RepositoryURL, "/repos/"); i >= 0 {
			repo = o.RepositoryURL[i+len("/repos/"):]
		}
	}
	if repo == "" || strings.Count(repo, "/") != 1 {
		return false
	}
	// Visibility for the public-repo baseline: the entry's own `private` (a repo object) or
	// its nested `repository.private` (an issue/search item). Unknown → private (fail closed),
	// so an entry whose shape omits visibility is never kept by the baseline.
	isPrivate := true
	if o.Private != nil {
		isPrivate = *o.Private
	} else if o.Repository.Private != nil {
		isPrivate = *o.Repository.Private
	}
	return authorized(repo, isPrivate)
}
