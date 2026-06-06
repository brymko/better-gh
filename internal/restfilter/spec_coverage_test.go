package restfilter

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"better-gh/internal/classifier"
	"better-gh/internal/restfilter/specderive"
)

func loadSpec(t *testing.T) *specderive.Spec {
	t.Helper()
	raw, err := os.ReadFile("testdata/api.github.com.json")
	if err != nil {
		t.Fatalf("read embedded spec: %v (run: curl -sL <api.github.com.json url> -o internal/restfilter/testdata/api.github.com.json)", err)
	}
	s, err := specderive.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSpecCoverage_TableIsCurrent proves the committed openapi_table.go is EXACTLY what regenerating from
// the embedded spec produces — so it is neither stale nor hand-edited. Combined with the classification
// invariants (TestCoverage_*), the whole chain is spec-grounded: table = derive(committed spec), and the
// hand tables cover the table.
func TestSpecCoverage_TableIsCurrent(t *testing.T) {
	repoOps, known := loadSpec(t).BuildTable()
	if !reflect.DeepEqual(repoOps, repoEnumOps) {
		for k, v := range repoOps {
			if !reflect.DeepEqual(repoEnumOps[k], v) {
				t.Errorf("repoEnumOps[%q] stale/hand-edited: committed=%v derived=%v", k, repoEnumOps[k], v)
			}
		}
		for k := range repoEnumOps {
			if _, ok := repoOps[k]; !ok {
				t.Errorf("repoEnumOps[%q] not derivable from the embedded spec (stale)", k)
			}
		}
	}
	wantKnown := append([]string(nil), knownGetOps...)
	sort.Strings(wantKnown)
	if !reflect.DeepEqual(known, wantKnown) {
		t.Errorf("knownGetOps differs from the embedded spec derivation (regenerate openapi_table.go)")
	}
}

// concretePath substitutes a path template's {param} segments so the real classifier can scope it:
// {owner}/{repo} become o/r (so /repos/{owner}/{repo}/… scopes to one repo), everything else a placeholder.
func concretePath(tmpl string) string {
	var out []string
	for _, seg := range strings.Split(tmpl, "/") {
		switch {
		case seg == "{owner}" || seg == "{template_owner}":
			out = append(out, "o")
		case seg == "{repo}" || seg == "{template_repo}":
			out = append(out, "r")
		case strings.HasPrefix(seg, "{"):
			out = append(out, "x")
		default:
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/")
}

// pathScopedSafeExceptions are ops the over-approximate scan flags but which cannot disclose a denied
// repo a client could not otherwise obtain — kept EXPLICIT, one per op with a specific justification, so
// a future spec change that adds a GENUINELY-foreign op is NOT silently allowlisted (it would be unlisted
// → flagged → re-triaged). Each was reviewed against the rule: a leak requires surfacing a denied repo's
// identity/content the client could not reach through an allowed path.
var pathScopedSafeExceptions = map[string]string{
	// the shared authentication-token schema carries repositories[], but GitHub populates it only for
	// installation access tokens — a runner registration/remove token response is {token, expires_at}.
	"POST /orgs/{org}/actions/runners/registration-token":           "runner token response is {token,expires_at}; repositories[] is schema-shared, never populated",
	"POST /orgs/{org}/actions/runners/remove-token":                 "runner token response is {token,expires_at}; repositories[] is schema-shared, never populated",
	"POST /repos/{owner}/{repo}/actions/runners/registration-token": "runner token response is {token,expires_at}; repositories[] is schema-shared, never populated",
	"POST /repos/{owner}/{repo}/actions/runners/remove-token":       "runner token response is {token,expires_at}; repositories[] is schema-shared, never populated",
	// creating an installation access token requires a GitHub App JWT the user-token custodian lacks;
	// GitHub denies, so its repositories[] never reaches a proxy client.
	"POST /app/installations/{installation_id}/access_tokens": "requires GitHub App JWT auth the user-token custodian lacks; GitHub denies",
	// migration / variant-analysis responses echo the repos the CLIENT specified as targets in the
	// request (and are gated behind migration / code-scanning write); not a new disclosure. The variant-
	// analysis GET result form IS redacted (repoEnumOps + string-array + per-bucket count).
	"POST /orgs/{org}/migrations": "echoes the client's own requested migration target repos; gated behind migration write",
	"POST /user/migrations":       "echoes the client's own requested migration target repos; gated behind migration write",
	"POST /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses": "echoes the client's own requested scan target repos; gated behind code-scanning write (GET form is redacted)",
}

// TestSpecCoverage_NoPathScopedLeak is the strong, spec-grounded boundary guarantee: for EVERY operation,
// an INDEPENDENT over-approximate scan (specderive.RepoReach — NOT the drop-table's own find()) finds
// whether the response can surface an ENUMERATED or FOREIGN (cross-ref) repository, and the test asserts
// the proxy's REAL decision (classifier scope + restfilter Lookup/Scrub tables) cannot stream it
// unredacted. A path-scoped op that surfaces a foreign/enumerated repo it neither drops (NeedsFilter) nor
// scrubs is a LEAK (the round-17/20/21 cross-ref / write-scrub class). Non-path-scoped ops are bounded by
// the Pass body-scan / off-spec fail-closed for the same (detectable) shapes RepoReach uses.
func TestSpecCoverage_NoPathScopedLeak(t *testing.T) {
	spec := loadSpec(t)
	var leaks []string
	for _, o := range spec.Ops() {
		reach := spec.RepoReach(o)
		if !reach.Any() {
			continue
		}
		if _, ok := pathScopedSafeExceptions[strings.ToUpper(o.Method)+" "+o.Path]; ok {
			continue
		}
		path := concretePath(o.Path)
		method := strings.ToUpper(o.Method)
		isGet := method == "GET" || method == "HEAD"
		cl := classifier.Classify(method, path, nil)
		pathScoped := cl.HasRepo()
		dec, _ := Lookup(path)
		covered := dec == NeedsFilter || len(ScrubLocations(path)) > 0 || len(ContentScrubFields(path)) > 0

		if isGet {
			// A GET's enumerated/foreign repos must be dropped/scrubbed only when the request is
			// PATH-scoped (a path-scoped Pass response streams). A non-path-scoped GET is bounded by the
			// Pass body-scan (ContainsDeniedRepo fails closed) / NeedsFilter / off-spec deny for the same
			// detectable shapes RepoReach uses, and a subject-only repo is the path repo (path-scoped) or
			// likewise body-scanned. So a GET leaks only if it is path-scoped AND surfaces an enumerated/
			// foreign repo it neither drops nor scrubs.
			if (reach.Enum || reach.Foreign) && pathScoped && !covered {
				leaks = append(leaks, method+" "+o.Path+leakWhy(reach, dec))
			}
			continue
		}

		// WRITE: the write path runs ONLY the cross-ref / content scrub (no enum redact, no passScan), so
		// a foreign/enumerated repo — OR a SUBJECT repo that is NOT the path repo (a non-path-scoped write
		// whose response subject is a different repo, e.g. a projectsV2 item's linked content) — must be
		// scrubbed/content-scrubbed. PER-LOCATION (not boolean): every FOREIGN cross-ref location RepoReach
		// finds must be covered EITHER by a write-scrub jsonpath naming its cross-ref field OR by a content-
		// scrub field that wholesale-nulls an ancestor — so a PARTIAL scrub (parent/source present but
		// template_repository absent — the /forks miss) is caught, not just a wholly-missing one (round-22).
		writeScrub := strings.Join(WriteScrubLocations(path), " ")
		contentFields := ContentScrubFields(path)
		for _, field := range unscrubbedForeignFields(reach, writeScrub, contentFields) {
			leaks = append(leaks, method+" "+o.Path+" [unscrubbed foreign cross-ref field: "+field+"]")
		}
		if reach.Enum || (reach.Subject && !pathScoped) {
			if len(WriteScrubLocations(path)) == 0 && len(contentFields) == 0 {
				leaks = append(leaks, method+" "+o.Path+leakWhy(reach, dec))
			}
		}
	}
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Fatalf("%d op(s) can surface a foreign/enumerated repository the proxy neither drops nor scrubs "+
			"(a cross-repo leak — add a NeedsFilter location, a scrub entry, or — if genuinely safe — a "+
			"justified pathScopedSafeExceptions entry):\n  %s", len(leaks), strings.Join(leaks, "\n  "))
	}
}

// unscrubbedForeignFields returns the cross-ref field names of FOREIGN repo locations RepoReach found
// that are NOT covered: a location is covered if its cross-ref field (parent/source/template_repository/
// head/base/…) is named by a write-scrub jsonpath, OR a content-scrub field wholesale-nulls an ancestor
// of the location (e.g. projectsV2 `content` nulls a nested PR head.repo). Uncovered names are leaks.
func unscrubbedForeignFields(reach specderive.RepoReach, writeScrub string, contentFields []string) []string {
	seen := map[string]bool{}
	for _, p := range reach.Paths {
		if !strings.HasPrefix(p, "FOREIGN:") {
			continue
		}
		loc := strings.TrimPrefix(p, "FOREIGN:")
		if coveredByContentField(loc, contentFields) {
			continue
		}
		for _, seg := range strings.Split(loc, ".") {
			seg = strings.TrimSuffix(seg, "[]")
			if specderive.IsCrossRefField(seg) && !strings.Contains(writeScrub, seg) {
				seen[seg] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// coveredByContentField reports whether a top-level content-scrub field wholesale-nulls an ancestor of
// loc (so any repo nested under it is dropped). loc is a "$.field.sub…" JSON path.
func coveredByContentField(loc string, contentFields []string) bool {
	for _, f := range contentFields {
		if loc == "$."+f || strings.HasPrefix(loc, "$."+f+".") || strings.HasPrefix(loc, "$."+f+"[") {
			return true
		}
	}
	return false
}

func leakWhy(r specderive.RepoReach, dec Decision) string {
	d := map[Decision]string{Pass: "Pass", NeedsFilter: "NeedsFilter", Unknown: "Unknown"}[dec]
	paths := r.Paths
	if len(paths) > 4 {
		paths = paths[:4]
	}
	return " [Lookup=" + d + "; " + strings.Join(paths, " ") + "]"
}
