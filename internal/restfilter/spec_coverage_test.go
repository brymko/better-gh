package restfilter

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"better-gh/internal/classifier"
	"better-gh/internal/restfilter/specderive"
)

// requestBodyRepoSafeExceptions are string-`repositories` request-body ops the CUSTODIAN token cannot
// reach, so naming a denied repo there discloses nothing — kept EXPLICIT so a NEW reachable body-naming op
// is flagged by TestSpecCoverage_RequestBodyNamedRepos instead of silently fail-open (the round-23 class).
var requestBodyRepoSafeExceptions = map[string]string{
	"POST /app/installations/{installation_id}/access_tokens": "requires a GitHub App JWT the user-token custodian lacks; GitHub denies",
	"POST /applications/{client_id}/token/scoped":             "requires the OAuth app's client_id:client_secret basic auth the custodian lacks; GitHub denies",
}

// TestSpecCoverage_RequestBodyNamedRepos is the REQUEST-side analogue of NoPathScopedLeak and the build-time
// guard for the recurring "a repo named in the request must become a scope" class (round-15/16/23): it
// derives from the embedded spec every POST/PUT/PATCH whose JSON body has a string-array `repositories`/
// `repository_owners` field, and asserts the classifier turns a body-named FOREIGN repo into a scope (so the
// policy can deny it) — unless the op is a justified unreachable exception. A new such op fails the build.
func TestSpecCoverage_RequestBodyNamedRepos(t *testing.T) {
	raw, err := os.ReadFile("testdata/api.github.com.json")
	if err != nil {
		t.Fatalf("read embedded spec: %v", err)
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var deref func(m map[string]any, depth int) map[string]any
	deref = func(m map[string]any, depth int) map[string]any {
		if m == nil || depth > 6 {
			return m
		}
		if ref, ok := m["$ref"].(string); ok {
			name := ref[strings.LastIndex(ref, "/")+1:]
			var sub map[string]any
			if json.Unmarshal(spec.Components.Schemas[name], &sub) == nil {
				return deref(sub, depth+1)
			}
		}
		return m
	}
	// a string-array property whose items are typed "string"
	stringArrayField := func(props map[string]any, name string) bool {
		f, _ := props[name].(map[string]any)
		f = deref(f, 0)
		if f == nil {
			return false
		}
		items, _ := deref(mapOf(f["items"]), 0)["type"].(string)
		return items == "string"
	}

	var leaks []string
	for path, methods := range spec.Paths {
		for method, rawOp := range methods {
			if method != "post" && method != "put" && method != "patch" {
				continue
			}
			var op struct {
				RequestBody struct {
					Content map[string]struct {
						Schema map[string]any `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			}
			if json.Unmarshal(rawOp, &op) != nil {
				continue
			}
			sch := deref(op.RequestBody.Content["application/json"].Schema, 0)
			props, _ := sch["properties"].(map[string]any)
			if props == nil || (!stringArrayField(props, "repositories") && !stringArrayField(props, "repository_owners")) {
				continue
			}
			key := strings.ToUpper(method) + " " + path
			if _, ok := requestBodyRepoSafeExceptions[key]; ok {
				continue
			}
			// The classifier must turn a body-named foreign repo into a scope.
			cp := concretePath(path)
			r := classifier.Classify(strings.ToUpper(method), cp, []byte(`{"repositories":["foreign-denied/secret"],"repository_owners":["foreign-denied"]}`))
			if !classifierScopesRepo(r, "foreign-denied", "secret") && !classifierScopesOrg(r, "foreign-denied") {
				leaks = append(leaks, key)
			}
		}
	}
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Fatalf("%d request-body op(s) name a repository the classifier does NOT scope (a denied repo could be "+
			"migrated/scanned/granted by the custodian — round-23 class): add it to bodyNamedRepoScopes, or, if "+
			"the custodian cannot reach it, to requestBodyRepoSafeExceptions:\n  %s", len(leaks), strings.Join(leaks, "\n  "))
	}
}

// TestSpecCoverage_PathNamedReposScoped is the REQUEST-PATH dual of NoPathScopedLeak: every spec path
// template that names a repository by {owner}/{repo} must produce a classifier scope for that repo, so a
// repo embedded DEEPER than the org/user prefix (the round-23 team-repo, the round-24 /user/starred and
// /networks feeds) cannot be read/written/probed under a coarser scope. A new such path fails the build.
func TestSpecCoverage_PathNamedReposScoped(t *testing.T) {
	raw, err := os.ReadFile("testdata/api.github.com.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var miss []string
	for path, methods := range spec.Paths {
		if !strings.Contains(path, "{owner}") || !strings.Contains(path, "{repo}") {
			continue
		}
		cp := concretePath(path)
		for method := range methods {
			m := strings.ToUpper(method)
			if m != "GET" && m != "PUT" && m != "POST" && m != "DELETE" && m != "PATCH" {
				continue
			}
			if !classifierScopesRepo(classifier.Classify(m, cp, nil), "o", "r") {
				miss = append(miss, m+" "+path)
			}
		}
	}
	if len(miss) > 0 {
		sort.Strings(miss)
		t.Fatalf("%d path(s) name a repository by {owner}/{repo} the classifier does NOT scope (it lives deeper "+
			"than the scoped prefix — the round-23/24 path-embedded class): add a pathEmbeddedRepoScopes case:\n  %s",
			len(miss), strings.Join(miss, "\n  "))
	}
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

// TestSpecCoverage_NestedBareNameRepos derives from the embedded spec every GET whose response nests a
// `repositories` array of BARE-`name` repo objects (no full_name/url/id — the shape the generator and the
// Pass body-scan can't locate) and asserts each is in nestedBareNameRepoOps, so a spec refresh adding
// another such op (the round-33 Copilot-metrics class) fails the build instead of silently leaking a denied
// repo's name (RepoReach's bare-name blind spot — these ops are otherwise skipped by NoPathScopedLeak).
func TestSpecCoverage_NestedBareNameRepos(t *testing.T) {
	raw, err := os.ReadFile("testdata/api.github.com.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var deref func(m map[string]any, depth int) map[string]any
	deref = func(m map[string]any, depth int) map[string]any {
		if m == nil || depth > 12 {
			return m
		}
		if ref, ok := m["$ref"].(string); ok {
			var sub map[string]any
			if json.Unmarshal(spec.Components.Schemas[ref[strings.LastIndex(ref, "/")+1:]], &sub) == nil {
				return deref(sub, depth+1)
			}
		}
		return m
	}
	var nestsBareNameRepos func(sch map[string]any, depth int) bool
	nestsBareNameRepos = func(sch map[string]any, depth int) bool {
		sch = deref(sch, depth)
		if sch == nil || depth > 12 {
			return false
		}
		props, _ := sch["properties"].(map[string]any)
		for name, p := range props {
			pm := deref(mapOf(p), depth)
			if name == "repositories" {
				items := deref(mapOf(pm["items"]), depth)
				ip, _ := items["properties"].(map[string]any)
				_, hasName := ip["name"]
				_, hasFull := ip["full_name"]
				_, hasURL := ip["url"]
				_, hasID := ip["id"]
				if hasName && !hasFull && !hasURL && !hasID {
					return true
				}
			}
			if nestsBareNameRepos(pm, depth+1) {
				return true
			}
		}
		if items, ok := pm2(sch["items"]); ok && nestsBareNameRepos(items, depth+1) {
			return true
		}
		return false
	}
	registered := map[string]bool{}
	for _, p := range nestedBareNameRepoOps {
		registered[p] = true
	}
	var missing []string
	for path, methods := range spec.Paths {
		rawOp, ok := methods["get"]
		if !ok {
			continue
		}
		var op struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema map[string]any `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		}
		if json.Unmarshal(rawOp, &op) != nil {
			continue
		}
		sch := op.Responses["200"].Content["application/json"].Schema
		if sch != nil && nestsBareNameRepos(sch, 0) && !registered[path] {
			missing = append(missing, "GET "+path)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d GET op(s) nest a bare-name repositories[] array but are NOT in nestedBareNameRepoOps — "+
			"they leak a denied repo's name (the Pass body-scan can't see a bare name): add them:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

func pm2(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func classifierScopesRepo(r classifier.Result, owner, repo string) bool {
	for _, s := range r.AllScopes() {
		if s.Owner == owner && s.Repo == repo {
			return true
		}
	}
	return false
}

func classifierScopesOrg(r classifier.Result, org string) bool {
	for _, s := range r.AllScopes() {
		if s.Org == org {
			return true
		}
	}
	return false
}

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
	// the migration response echoes the repos named in the request body, but the classifier now scopes
	// EVERY body `repositories[]` target as its own policy scope (bodyNamedRepoScopes), so a denied target
	// is rejected at the front gate before any migration runs — the only repos that reach the response are
	// ones the policy already allows. TestBodyNamedReposScoped proves this holds, so the exception cannot
	// silently regress to the round-23 fail-open (a denied repo named in the body, unscoped, archived by the
	// custodian). NOT the original false "client only names its own repos" justification.
	"POST /orgs/{org}/migrations": "classifier body-scopes every repositories[] target (bodyNamedRepoScopes) → denied target rejected pre-response; see TestBodyNamedReposScoped",
	"POST /user/migrations":       "classifier body-scopes every repositories[] target (bodyNamedRepoScopes) → denied target rejected pre-response; see TestBodyNamedReposScoped",
	// (POST variant-analyses is NOT here: body-scoping covers repositories[]/repository_owners[], and the
	// response is additionally content-scrubbed for the unresolvable repository_lists form — so it is
	// covered by the normal path, not an exception.)
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
