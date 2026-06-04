package restfilter

// Cross-reference content scrub table (hand-maintained — see below).
//
// A few REST responses embed, inside a heterogeneous array, a FULL foreign-repo CONTENT object
// reached through a cross-reference field. The canonical case is the issue timeline: a
// `cross-referenced` event's `source.issue` is a complete issue (title + body + repository) in
// ANOTHER, possibly policy-denied, repo. The classifier scopes the request only to the PATH repo
// (which is allowed), so without redaction the denied repo's issue contents stream to the client
// (audit F2).
//
// The generated repoEnumOps table cannot express this: its generator deliberately skips
// cross-reference fields (head/base/source/parent/forkee/…) so a single-repo endpoint like
// /pulls isn't dropped because a PR's head fork is denied — and even if it emitted the location,
// the enum redactor DROPS the whole array element, which would delete every non-cross-ref event
// (labeled/assigned/commented/…) since they expose no repo. The correct operation is a per-element
// SCRUB: null just the cross-ref sub-object when its repo is denied, keeping the event. That is
// what restfilter.Scrub does, driven by this table.
//
// Maintenance: this is intentionally tiny and hand-maintained — the cross-ref-content pattern is
// rare and structural, and a regeneration of openapi_table.go does NOT touch this file. When
// refreshing against a new GitHub OpenAPI spec, audit sibling endpoints that embed a
// `cross-referenced`/`source` issue (e.g. activity/event feeds) and add them here. Each location
// addresses the foreign repo's full_name through the cross-ref wrapper; Scrub nulls the wrapper
// (the first field after the array — here `source`) per element when that repo is denied.
var repoScrubOps = map[string][]string{
	"GET /repos/{owner}/{repo}/issues/{issue_number}/timeline": {"$[].source.issue.repository.full_name"},
}
