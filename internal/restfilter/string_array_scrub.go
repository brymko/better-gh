package restfilter

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Bare-string repository-array scrub table (hand-maintained — see below).
//
// A few REST responses name repositories as PLAIN "owner/repo" STRINGS inside a string array rather
// than as objects carrying a `full_name`/`repository_url`. The OpenAPI-driven generator
// (internal/restfilter/gen) only locates repository identities via the object shapes (a `full_name`
// property or the minimal {id,name,url} repo object), so a bare-string array is invisible to it: no
// location is emitted and the array is never redacted (round-19 F4).
//
// The canonical case is the CodeQL variant analysis:
//   GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{id}
// whose skipped_repositories has THREE object buckets (access_mismatch_repos / no_codeql_db_repos /
// over_limit_repos — each [{full_name}], correctly located + dropped by Redact) and a FOURTH,
// not_found_repos, which is {repository_count, repository_full_names:["owner/repo", …]} — plain
// strings the generator can't locate. Left unredacted, a client allowed to read the controller repo
// learns the exact NAMES/existence of private repos its policy denies. DropRepoStrings drops each
// denied "owner/repo" from the array and decrements the sibling count.
//
// Maintenance: this is intentionally hand-maintained (like crossref_scrub.go); generated enum
// locations do NOT touch it. "*_full_names"-style string arrays belong here.

// stringRepoArrayLoc addresses a bare-string "owner/repo" array inside an object, plus an optional
// sibling count field to decrement when entries are dropped.
type stringRepoArrayLoc struct {
	container  []string // field path from the response root to the object holding the array
	arrayField string   // the bare-string "owner/repo" array
	countField string   // sibling integer count to decrement by the number dropped ("" = none)
}

var repoStringArrayOps = map[string][]stringRepoArrayLoc{
	"GET /repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}": {
		{container: []string{"skipped_repositories", "not_found_repos"}, arrayField: "repository_full_names", countField: "repository_count"},
	},
}

type stringArrayTemplate struct {
	tmpl opTemplate
	locs []stringRepoArrayLoc
}

var stringArrayTemplates []stringArrayTemplate

func init() {
	for key, locs := range repoStringArrayOps {
		stringArrayTemplates = append(stringArrayTemplates, stringArrayTemplate{
			tmpl: parseTemplate(strings.TrimPrefix(key, "GET "), nil),
			locs: locs,
		})
	}
}

// StringArrayLocations returns the bare-string repo-array scrub locations for normPath, or nil.
func StringArrayLocations(normPath string) []stringRepoArrayLoc {
	ps := segments(normPath)
	for _, t := range stringArrayTemplates {
		if t.tmpl.matches(ps) {
			return t.locs
		}
	}
	return nil
}

// DropRepoStrings drops denied "owner/repo" strings from each bare-string repo array and decrements
// the sibling count. It FAILS CLOSED (ok=false) on a non-empty body it cannot parse, like Redact; an
// empty body passes through. authorized receives "owner/repo".
func DropRepoStrings(body []byte, locs []stringRepoArrayLoc, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	for _, loc := range locs {
		container, ok := walkToObject(root, loc.container)
		if !ok {
			continue
		}
		arr, ok := container[loc.arrayField].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(arr))
		dropped := 0
		for _, el := range arr {
			if s, ok := el.(string); ok && strings.Count(s, "/") == 1 && !authorized(s) {
				dropped++
				continue
			}
			kept = append(kept, el)
		}
		container[loc.arrayField] = kept
		if dropped > 0 && loc.countField != "" {
			if _, has := container[loc.countField]; has {
				container[loc.countField] = json.Number(strconv.Itoa(maxInt(0, jsonNumberToInt(container[loc.countField])-dropped)))
			}
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

func walkToObject(root any, path []string) (map[string]any, bool) {
	cur := root
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = m[p]
	}
	m, ok := cur.(map[string]any)
	return m, ok
}
