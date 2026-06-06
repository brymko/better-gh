package restfilter

// Cross-reference content scrub table (hand-maintained — see below).
//
// A few REST responses embed, inside an array element OR on the response object itself, a FULL
// foreign-repo object reached through a cross-reference field. The canonical cases:
//   - issue timeline: a `cross-referenced` event's `source.issue` is a complete issue (title + body
//     + repository) in ANOTHER, possibly policy-denied, repo (audit round-13 F2).
//   - GET /repos/{o}/{r} on a fork/template repo embeds `parent` / `source` / `template_repository`,
//     each a full Repository (name/description/private/clone_url) of a different, possibly denied
//     upstream repo (round-15 REST-COV-1).
//   - the event feeds embed `payload.forkee` (ForkEvent) and `payload.pull_request.head/base.repo`
//     (PR events) — a denied repo's metadata the per-element repo.name drop can't reach (REST-COV-2).
//
// The generated repoEnumOps table cannot express these: its generator deliberately skips
// cross-reference fields (head/base/source/parent/forkee/template_repository/…) so a single-repo
// endpoint like /pulls isn't dropped because a PR's head fork is denied — and even if it emitted the
// location, the enum redactor DROPS the whole array element, which would delete every non-cross-ref
// row. The correct operation is a SCRUB: null just the cross-ref sub-object when its repo is denied,
// keeping the surrounding row/object. That is what restfilter.Scrub does, driven by this table.
//
// Location syntax: a '*' prefixes the field to NULL when the repo read at the end of the path is
// denied; "[]" is an array of elements; the terminal segment names the foreign repo's full_name.
// e.g. "$[].payload.*forkee.full_name" nulls each element's payload.forkee when forkee's repo is
// denied; "$.*parent.full_name" nulls the response's own parent object when denied.
//
// Maintenance: this is intentionally hand-maintained — the cross-ref-content pattern is rare and
// structural, and a regeneration of openapi_table.go does NOT touch this file. When refreshing
// against a new GitHub OpenAPI spec, audit sibling endpoints that embed a cross-referenced/source/
// fork/parent object and add them here.

// eventForeignRepoLocs are the cross-ref repo objects an activity-event element can embed: the new
// fork (ForkEvent.payload.forkee) and a PR's head/base repo (PullRequestEvent etc.). Each is nulled
// per element when its repo is denied, leaving the event row intact.
var eventForeignRepoLocs = []string{
	"$[].payload.*forkee.full_name",
	"$[].payload.pull_request.head.*repo.full_name",
	"$[].payload.pull_request.base.*repo.full_name",
}

var repoScrubOps = map[string][]string{
	"GET /repos/{owner}/{repo}/issues/{issue_number}/timeline": {"$[].*source.issue.repository.full_name"},

	// fork/template upstream metadata embedded on the repo object itself (singleton scrub).
	"GET /repos/{owner}/{repo}": {"$.*parent.full_name", "$.*source.full_name", "$.*template_repository.full_name"},

	// A pull request embeds head.repo and base.repo as FULL Repository objects; for a PR opened
	// from a fork (forks of a private repo are themselves private), head.repo is a DIFFERENT,
	// possibly policy-denied repo than the path repo. These endpoints are repo-path-scoped Pass (the
	// generator skips head/base — gen/main.go crossRefFields — so /pulls isn't element-dropped on a
	// denied fork), so without a scrub entry the foreign fork's full_name/description/private flag/
	// owner stream unredacted (a denied-repo metadata + existence leak; the GraphQL headRepository
	// equivalent IS redacted — round-17). Null just head.repo / base.repo when its repo is denied,
	// keeping the PR row. The {pull_number} singleton over-matches sibling 5-segment /pulls/* paths
	// (e.g. /pulls/comments) by segment count, but those carry no head/base object so the scrub is a
	// harmless no-op there.
	"GET /repos/{owner}/{repo}/pulls":                      {"$[].head.*repo.full_name", "$[].base.*repo.full_name"},
	"GET /repos/{owner}/{repo}/pulls/{pull_number}":        {"$.head.*repo.full_name", "$.base.*repo.full_name"},
	"GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls": {"$[].head.*repo.full_name", "$[].base.*repo.full_name"},

	// A check run embeds pull_requests[].head/base.repo as MINIMAL {id,url,name} repos. GitHub's own
	// schema does NOT guarantee these are same-repo (the description only says "head_sha/head_branch
	// matches the check"), so a fork PR's head.repo could be a denied private repo — null it (gated via
	// the api `url`, since the minimal repo has no full_name) when denied (round-21). The check-suite/
	// commit forms nest the runs one level deeper (check_runs[].pull_requests[]).
	"GET /repos/{owner}/{repo}/check-runs/{check_run_id}":                {"$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs": {"$.check_runs[].pull_requests[].head.*repo.url", "$.check_runs[].pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/commits/{ref}/check-runs":                 {"$.check_runs[].pull_requests[].head.*repo.url", "$.check_runs[].pull_requests[].base.*repo.url"},

	// A check-SUITE (singleton + the commits/{ref}/check-suites list) embeds pull_requests[].head/base.repo
	// as MINIMAL {id,url,name} repos GitHub does NOT guarantee are same-repo — a fork PR's head.repo is a
	// possibly-denied private fork. Only check-suites/{id}/check-runs was scrubbed before, so the bare suite
	// ops streamed the fork identity (round-43 F4). Null by the api `url` (minimal repo has no full_name).
	"GET /repos/{owner}/{repo}/check-suites/{check_suite_id}": {"$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/commits/{ref}/check-suites":    {"$.check_suites[].pull_requests[].head.*repo.url", "$.check_suites[].pull_requests[].base.*repo.url"},

	// A workflow-RUN embeds head_repository (a full minimal-repository: name/full_name/private/owner) of the
	// fork that produced a fork-originated run, plus pull_requests[].head/base.repo (minimal {id,url,name}).
	// Keyed only on the run's OWN repository (the allowed path repo), so a fork-originated run on an allowed
	// repo streamed the denied fork's metadata + PR head/base fork identity (round-43 F4). The list ops wrap
	// in workflow_runs[]; the singleton run + attempt forms carry the run object directly. The GraphQL
	// WorkflowRun.headRepository twin IS already redacted (crossRepoNavFields) — close the one-sided REST gap.
	"GET /repos/{owner}/{repo}/actions/runs":                                    {"$.workflow_runs[].*head_repository.full_name", "$.workflow_runs[].pull_requests[].head.*repo.url", "$.workflow_runs[].pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs":            {"$.workflow_runs[].*head_repository.full_name", "$.workflow_runs[].pull_requests[].head.*repo.url", "$.workflow_runs[].pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/actions/runs/{run_id}":                           {"$.*head_repository.full_name", "$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},
	"GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}": {"$.*head_repository.full_name", "$.pull_requests[].head.*repo.url", "$.pull_requests[].base.*repo.url"},

	// activity event feeds (forkee + PR head/base repo).
	"GET /events":                                  eventForeignRepoLocs,
	"GET /networks/{owner}/{repo}/events":          eventForeignRepoLocs,
	"GET /orgs/{org}/events":                       eventForeignRepoLocs,
	"GET /repos/{owner}/{repo}/events":             eventForeignRepoLocs,
	"GET /users/{username}/events":                 eventForeignRepoLocs,
	"GET /users/{username}/events/orgs/{org}":      eventForeignRepoLocs,
	"GET /users/{username}/events/public":          eventForeignRepoLocs,
	"GET /users/{username}/received_events":        eventForeignRepoLocs,
	"GET /users/{username}/received_events/public": eventForeignRepoLocs,
}
