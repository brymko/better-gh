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
	case len(s) == 3 && s[0] == "orgs" && (s[2] == "repos" || s[2] == "issues" || s[2] == "events"):
		return true
	case len(s) == 3 && s[0] == "users" && (s[2] == "repos" || s[2] == "starred" || s[2] == "subscriptions" || s[2] == "events" || s[2] == "received_events"):
		return true
	case len(s) == 4 && s[0] == "repos" && s[3] == "forks":
		// /repos/{owner}/{repo}/forks returns repository objects owned by OTHERS; the GraphQL
		// filter already redacts `forks`, so redact here too (the parent repo is policy-checked
		// by the classifier; denied forks are dropped by full_name).
		return true
	case len(s) == 4 && s[0] == "orgs" && s[3] == "alerts" && (s[2] == "secret-scanning" || s[2] == "dependabot" || s[2] == "code-scanning"):
		// Org-wide alert feeds aggregate per-repo data across EVERY repo in the org (the custodian
		// can read all of them) — and secret-scanning alerts carry the cleartext `secret`. The
		// classifier scopes these to the org only, so a per-repo `none` carve-out never applies;
		// without redaction they leak the carved-out repo's alerts/secrets (round-12 audit H4).
		// Each entry carries repository.full_name, which repoAllowed handles.
		return true
	case len(s) == 5 && s[0] == "orgs" && s[2] == "teams" && s[4] == "repos":
		return true // /orgs/{org}/teams/{team}/repos → repository objects (full_name)
	case isMigrationsContainer(s):
		return true // /{orgs/{org},user}/migrations[/{id}] → migration objects nesting repositories[]
	case len(s) == 5 && s[0] == "orgs" && s[2] == "migrations" && s[4] == "repositories":
		return true // /orgs/{org}/migrations/{id}/repositories → plain repo array
	case len(s) == 4 && s[0] == "user" && s[1] == "migrations" && s[3] == "repositories":
		return true // /user/migrations/{id}/repositories → plain repo array
	case len(s) == 1 && (s[0] == "repositories" || s[0] == "issues" || s[0] == "notifications" || s[0] == "events"):
		return true
	case len(s) == 2 && s[0] == "search" && (s[1] == "repositories" || s[1] == "code" || s[1] == "issues" || s[1] == "commits"):
		return true
	}
	return false
}

// isMigrationsContainer reports whether normPath's segments are a migrations LIST or single
// migration OBJECT (each of which nests a repositories[] of MANY repos), as opposed to the
// .../migrations/{id}/repositories sub-path (a plain repo array handled by filterArray).
func isMigrationsContainer(s []string) bool {
	if len(s) > 0 && s[len(s)-1] == "repositories" {
		return false
	}
	switch {
	case len(s) == 3 && s[0] == "orgs" && s[2] == "migrations": // /orgs/{org}/migrations (list)
		return true
	case len(s) == 4 && s[0] == "orgs" && s[2] == "migrations": // /orgs/{org}/migrations/{id}
		return true
	case len(s) == 2 && s[0] == "user" && s[1] == "migrations": // /user/migrations (list)
		return true
	case len(s) == 3 && s[0] == "user" && s[1] == "migrations": // /user/migrations/{id}
		return true
	}
	return false
}

// Filter redacts denied-repo entries from a recognized enumeration/search response.
// authorized receives "owner/repo". Repo-list / issue-list endpoints return a JSON array;
// search endpoints return {items:[...], total_count, ...}; migration objects nest a
// repositories[] array that is redacted in place. An off-shape body (e.g. an error object) is
// returned unchanged.
func Filter(normPath string, body []byte, authorized func(ownerRepo string) bool) []byte {
	s := segments(normPath)
	if len(s) >= 1 && s[0] == "search" {
		return filterSearch(body, authorized)
	}
	if isMigrationsContainer(s) {
		return filterMigrations(body, authorized)
	}
	return filterArray(body, authorized)
}

// filterMigrations redacts denied repos from the nested repositories[] of each migration. A
// migration object mixes allowed and denied repos and carries non-repo metadata (id, state, …),
// so — unlike the drop-whole-entry endpoints — the entry is kept and only its repositories[] is
// filtered. Handles both the list ([{…,repositories:[…]}, …]) and single-object ({…}) shapes.
func filterMigrations(body []byte, authorized func(string) bool) []byte {
	var arr []json.RawMessage
	if json.Unmarshal(body, &arr) == nil {
		for i, raw := range arr {
			arr[i] = redactMigrationRepos(raw, authorized)
		}
		if out, err := json.Marshal(arr); err == nil {
			return out
		}
		return body
	}
	return redactMigrationRepos(body, authorized) // single migration object
}

// redactMigrationRepos rewrites one migration object's repositories[] to keep only allowed repos.
// An object with no repositories field (or a non-object) is returned unchanged.
func redactMigrationRepos(raw json.RawMessage, authorized func(string) bool) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return raw
	}
	reposRaw, ok := obj["repositories"]
	if !ok {
		return raw
	}
	obj["repositories"] = filterArray(reposRaw, authorized) // repo objects carry full_name
	if out, err := json.Marshal(obj); err == nil {
		return out
	}
	return raw
}

func filterArray(body []byte, authorized func(string) bool) []byte {
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

func filterSearch(body []byte, authorized func(string) bool) []byte {
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
func repoAllowed(raw json.RawMessage, authorized func(string) bool) bool {
	var o struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
		Owner    struct {
			Login string `json:"login"`
		} `json:"owner"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		// `repo` is the events shape ({repo:{name:"owner/repo"}}) and the starred/subscriptions
		// star+json wrapper ({starred_at, repo:{full_name:"owner/repo"}}). Note events'
		// repo.name is the FULL "owner/repo" (unlike a repository object's bare name).
		Repo struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
		} `json:"repo"`
		RepositoryURL string `json:"repository_url"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return false
	}
	repo := o.FullName
	if repo == "" {
		repo = o.Repository.FullName
	}
	if repo == "" {
		repo = o.Repo.FullName
	}
	if repo == "" && strings.Count(o.Repo.Name, "/") == 1 {
		repo = o.Repo.Name // events: repo.name is "owner/repo"
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
	return authorized(repo)
}
