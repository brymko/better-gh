package restfilter

// Write-response cross-reference scrub (hand-maintained — see crossref_scrub.go for the read side).
//
// GitHub WRITE endpoints echo the SAME foreign-repo cross-reference objects their GET siblings do —
// a pull request's head.repo/base.repo (a fork of a private repo is itself private), a repository's
// parent/source/template_repository — but the proxy's REST response-isolation block runs only for
// GET/HEAD, so a write response streamed those foreign-repo objects unredacted: PATCH/POST
// /repos/{o}/{r}/pulls returns head.repo of a fork-originated PR, and PATCH /repos/{o}/{r} returns
// the upstream parent/source of a fork (round-20). These singleton scrub locations are applied to
// write responses too, nulling just the foreign sub-object when its repo is denied while keeping the
// authorized write result.
//
// All entries are SINGLETON scrubs (a write returns the single created/updated object), keyed by
// segment template and matched method-agnostically; applying a singleton scrub to an unrelated body
// is a harmless no-op (scrubFields no-ops on a non-map root), so a stray GET that matches is unaffected.
var writeScrubOps = map[string][]string{
	// PATCH /repos/{o}/{r} returns the repository object, which for a fork/generated repo embeds the
	// upstream parent/source/template_repository (a different, possibly-denied repo).
	"/repos/{owner}/{repo}": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	// POST /repos/{o}/{r}/forks creates a fork (HTTP 202) whose full-repository body carries
	// parent/source AND template_repository — if the forked repo was itself generated from a private
	// template the client can't read, template_repository names that denied repo. The round-20 scrub
	// here covered only parent/source (the 202 response was invisible to the spec-coverage scan, which
	// inspected 200/201 only); round-22 adds template_repository.
	"/repos/{owner}/{repo}/forks": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	// POST /repos/{o}/{r}/security-advisories/{ghsa_id}/forks creates a temporary private fork (HTTP 202)
	// to fix an advisory; its full-repository body carries parent/source/template_repository just like
	// /forks. It had NO scrub entry at all (so respFilter stayed nil and the whole body streamed), the
	// other 202 sibling the spec-coverage scan was blind to (round-22).
	"/repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	// POST (create) and PATCH (update) a pull request return the PR with head.repo/base.repo as full
	// Repository objects; head.repo of a fork-originated PR is a different, possibly-denied private repo.
	"/repos/{owner}/{repo}/pulls":               {"$.head.*repo.full_name", "$.base.*repo.full_name"},
	"/repos/{owner}/{repo}/pulls/{pull_number}": {"$.head.*repo.full_name", "$.base.*repo.full_name"},
	// Repo-CREATE responses echo the upstream parent/source/template_repository the new repo was forked/
	// generated from — a possibly-denied private repo — the exact sibling of the round-20 PATCH
	// /repos/{o}/{r} scrub, missed on the create paths (round-21, surfaced by the spec-coverage test).
	"/orgs/{org}/repos": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	"/user/repos":       {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	"/repos/{template_owner}/{template_repo}/generate": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},
	// Publishing a codespace creates a repo; its `repository` carries the upstream parent/source.
	"/user/codespaces/{codespace_name}/publish": {"$.repository.*parent.full_name", "$.repository.*source.full_name", "$.repository.*template_repository.full_name"},
	// Creating/updating a check-run (POST/PATCH) or a check-suite returns pull_requests[].head/base.repo
	// (minimal {id,url,name}); a fork PR's head.repo could be a denied repo — null it via its url (round-21).
	"/repos/{owner}/{repo}/check-runs":                {"$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	"/repos/{owner}/{repo}/check-runs/{check_run_id}": {"$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	"/repos/{owner}/{repo}/check-suites":              {"$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	// POST/DELETE .../requested_reviewers ('Request reviewers' / 'Remove requested reviewers') return the
	// SAME full pull-request object (head.repo/base.repo). The round-20 table covered only /pulls and
	// /pulls/{n}; this deeper PR sub-resource that also returns the PR was missed, leaking a fork-
	// originated PR's denied head.repo on the write (round-21). The GET sibling returns only {users,teams}
	// (no head/base.repo), which is why the GET scrub table legitimately omits it.
	"/repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers": {"$.head.*repo.full_name", "$.base.*repo.full_name"},
}

var writeScrubTemplates []opTemplate

func init() {
	for key, locs := range writeScrubOps {
		writeScrubTemplates = append(writeScrubTemplates, parseTemplate(key, locs))
	}
}

// WriteScrubLocations returns the singleton cross-ref scrub locations for a write to normPath, or
// nil. The proxy runs restfilter.Scrub with these on write responses so a denied foreign repo's
// head/base/parent/source metadata is nulled — the write analogue of the GET-path ScrubLocations.
func WriteScrubLocations(normPath string) []string {
	ps := segments(normPath)
	for _, t := range writeScrubTemplates {
		if t.matches(ps) {
			return t.locs
		}
	}
	return nil
}
