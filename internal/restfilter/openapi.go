package restfilter

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Decision tells the proxy how to handle a GET response, derived from GitHub's OpenAPI
// description (see internal/restfilter/gen) rather than a hand-maintained allowlist.
type Decision int

const (
	// Pass: a known GET whose response carries no repository — forward unchanged.
	Pass Decision = iota
	// NeedsFilter: a known GET whose response carries repositories — redact denied ones (Redact).
	NeedsFilter
	// Unknown: the path matches no GET operation in the spec — off-spec. The proxy fails
	// closed for these (unless the classifier already scoped them to one repository).
	Unknown
)

type opTemplate struct {
	segs []string // literal segment, or "" for a {param} wildcard
	locs []string // repository-identity locations (set only for repo-bearing ops)
}

var (
	enumTemplates  []opTemplate // repo-bearing GET ops (Redact: drop denied elements)
	scrubTemplates []opTemplate // GET ops embedding foreign-repo cross-ref content (Scrub: null it in place)
	knownTemplates []opTemplate // every GET op (to tell Pass from Unknown)
)

func init() {
	for key, locs := range repoEnumOps {
		enumTemplates = append(enumTemplates, parseTemplate(strings.TrimPrefix(key, "GET "), locs))
	}
	for key, locs := range repoScrubOps {
		scrubTemplates = append(scrubTemplates, parseTemplate(strings.TrimPrefix(key, "GET "), locs))
	}
	for _, p := range knownGetOps {
		knownTemplates = append(knownTemplates, parseTemplate(p, nil))
	}
}

func parseTemplate(path string, locs []string) opTemplate {
	var segs []string
	for _, s := range segments(path) {
		if strings.HasPrefix(s, "{") {
			segs = append(segs, "")
		} else {
			segs = append(segs, s)
		}
	}
	return opTemplate{segs: segs, locs: locs}
}

func (t opTemplate) matches(pathSegs []string) bool {
	if len(t.segs) != len(pathSegs) {
		return false
	}
	for i, s := range t.segs {
		if s != "" && s != pathSegs[i] {
			return false
		}
	}
	return true
}

// Lookup classifies a normalized GET path against the spec: Redact (with repo-identity
// locations), Pass, or Unknown. Templates with a greedy/multi-segment param (e.g. the contents
// {path}) won't match by segment count and fall to Unknown — harmless, since those are
// single-repo paths the classifier already scopes and the proxy forwards.
func Lookup(normPath string) (Decision, []string) {
	ps := segments(normPath)
	for _, t := range enumTemplates {
		if t.matches(ps) {
			return NeedsFilter, t.locs
		}
	}
	for _, t := range knownTemplates {
		if t.matches(ps) {
			return Pass, nil
		}
	}
	return Unknown, nil
}

// Redact parses a repo-bearing GET response and drops denied repositories at the given
// locations. It FAILS CLOSED (ok=false) on a non-empty body it cannot parse, on a declared
// singleton repository whose identity is absent/malformed, or on a body where none of the declared
// array repository locations can be observed. An empty body (e.g. a 304) is passed through.
// authorized receives "owner/repo".
func Redact(body []byte, locs []string, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	// Singleton (non-array) locations address the response's OWN subject repository (a
	// notification thread, a codespace, a single package). If that repo is denied, the WHOLE
	// body belongs to a denied repo and its same-repo siblings would survive a mere sub-object
	// null; if the repo identity is absent/malformed, the proxy cannot prove the subject repo.
	var arrayLocs []string
	observed := false
	for _, loc := range locs {
		steps := parseLoc(loc)
		if len(steps) == 0 {
			continue
		}
		hasArray := false
		for _, s := range steps {
			if s.array {
				hasArray = true
				break
			}
		}
		if hasArray {
			arrayLocs = append(arrayLocs, loc)
			continue
		}
		repo, ok := readSingletonRepo(root, steps)
		if !ok {
			return nil, false
		}
		observed = true
		if !authorized(repo) {
			return nil, false
		}
	}
	dropped := 0
	var arrayObserved bool
	root, arrayObserved = applyLocations(root, arrayLocs, authorized, &dropped)
	observed = observed || arrayObserved
	if len(locs) > 0 && !observed {
		return nil, false
	}
	// Close the count oracle: if denied-repo elements were dropped and the body reports a
	// total_count, reduce it by the number dropped (and flag it incomplete) so the count can't
	// reveal how many denied-repo entries existed. Generalized from the {items,total_count} search
	// shape to EVERY enum body that carries a total_count alongside a repo array — {repositories[],
	// total_count}, {codespaces[],total_count}, … — which the old items-only rewrite left as a
	// denied-repo existence/count oracle (round-16 L).
	if m, ok := root.(map[string]any); ok && dropped > 0 {
		if tc, has := m["total_count"]; has {
			m["total_count"] = json.Number(strconv.Itoa(maxInt(0, jsonNumberToInt(tc)-dropped)))
			m["incomplete_results"] = true
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

// jsonNumberToInt reads an integer from a decoded JSON number (json.Number after UseNumber, or a
// float64); 0 on anything else. Used to adjust total_count when denied entries are dropped.
func jsonNumberToInt(v any) int {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case float64:
		return int(n)
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type locStep struct {
	field string
	array bool
}

// parseLoc turns "$.items[].repository.full_name" into ordered steps (field "items", array,
// field "repository", field "full_name").
func parseLoc(loc string) []locStep {
	var steps []locStep
	for _, part := range strings.Split(strings.TrimPrefix(loc, "$"), ".") {
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "[]") {
			if name := strings.TrimSuffix(part, "[]"); name != "" {
				steps = append(steps, locStep{field: name})
			}
			steps = append(steps, locStep{array: true})
		} else {
			steps = append(steps, locStep{field: part})
		}
	}
	return steps
}

// applyLocations redacts denied repositories addressed by all of an endpoint's array locations.
// Locations that filter the SAME array are evaluated together per element (an element is kept
// only if it exposes at least one determinable repository and ALL exposed repositories are
// allowed) — so an element isn't dropped merely because one location's optional path is absent
// (e.g. a PushEvent has repo.name but no payload.issue.repository). The returned observed flag
// reports whether at least one declared target array shape was actually present.
func applyLocations(root any, locs []string, authorized func(string) bool, dropped *int) (any, bool) {
	type group struct {
		prefix []locStep
		elems  [][]locStep
	}
	groups := map[string]*group{}
	var order []string
	for _, loc := range locs {
		steps := parseLoc(loc)
		if len(steps) == 0 {
			continue
		}
		last := -1
		for i, s := range steps {
			if s.array {
				last = i
			}
		}
		if last < 0 {
			continue // singleton locs are handled fail-closed in Redact, not here
		}
		prefix, elem := steps[:last], steps[last+1:]
		key := prefixKey(prefix)
		g := groups[key]
		if g == nil {
			g = &group{prefix: prefix}
			groups[key] = g
			order = append(order, key)
		}
		g.elems = append(g.elems, elem)
	}
	observed := false
	for _, key := range order {
		g := groups[key]
		var ok bool
		root, ok = descendGroup(root, g.prefix, g.elems, authorized, dropped)
		observed = observed || ok
	}
	return root, observed
}

func prefixKey(prefix []locStep) string {
	var b strings.Builder
	for _, s := range prefix {
		if s.array {
			b.WriteString("[]")
		} else {
			b.WriteByte('.')
			b.WriteString(s.field)
		}
	}
	return b.String()
}

// descendGroup walks prefix steps to the target array, then keeps only elements elementAllowed
// accepts. Recurses through any arrays in the prefix (e.g. migrations' $[].repositories[]).
// The returned observed flag is true only when the declared target array shape was present.
func descendGroup(cur any, prefix []locStep, elems [][]locStep, authorized func(string) bool, dropped *int) (any, bool) {
	if len(prefix) == 0 {
		arr, ok := cur.([]any)
		if !ok {
			return cur, false
		}
		kept := make([]any, 0, len(arr))
		for _, el := range arr {
			if elementAllowed(el, elems, authorized) {
				kept = append(kept, el)
			}
		}
		*dropped += len(arr) - len(kept)
		return kept, true
	}
	s := prefix[0]
	if s.array {
		arr, ok := cur.([]any)
		if !ok {
			return cur, false
		}
		if len(arr) == 0 {
			return arr, true
		}
		observed := false
		for i := range arr {
			var ok bool
			arr[i], ok = descendGroup(arr[i], prefix[1:], elems, authorized, dropped)
			observed = observed || ok
		}
		return arr, observed
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return cur, false
	}
	v, present := m[s.field]
	if !present {
		return cur, false
	}
	before := *dropped
	var observed bool
	m[s.field], observed = descendGroup(v, prefix[1:], elems, authorized, dropped)
	// If this field's array had denied entries dropped, decrement a sibling per-bucket
	// repository_count (the CodeQL variant-analysis skip buckets carry one per object) so it can't
	// serve as a denied-repo existence/count oracle — the per-bucket analogue of the root total_count
	// rewrite, which the round-16 root-only adjustment missed (round-21). total_count is handled once
	// at the root in Redact; only repository_count is touched here to avoid double-counting.
	if d := *dropped - before; d > 0 {
		if c, ok := m["repository_count"]; ok {
			m["repository_count"] = json.Number(strconv.Itoa(maxInt(0, jsonNumberToInt(c)-d)))
		}
	}
	return cur, observed
}

// elementAllowed keeps an array element iff it exposes at least one determinable repository
// (across the group's element-paths) and every exposed repository is allowed. An element that
// exposes none is dropped (fail closed).
func elementAllowed(el any, elems [][]locStep, authorized func(string) bool) bool {
	found := false
	for _, e := range elems {
		repo := readRepo(el, e)
		if repo == "" {
			continue
		}
		found = true
		if !authorized(repo) {
			return false
		}
	}
	return found
}

// readRepo follows elem (field steps ending in full_name/name) to the "owner/repo" string, or
// "" if absent/malformed.
func readRepo(v any, elem []locStep) string {
	for _, s := range elem {
		if s.array {
			return ""
		}
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		v = m[s.field]
	}
	str, _ := v.(string)
	if strings.Count(str, "/") != 1 {
		return ""
	}
	return str
}

// readSingletonRepo reads the "owner/repo" a non-array location points at (e.g.
// $.repository.full_name or $.full_name → the response's own subject repo). ok=false when the
// field is absent/malformed.
func readSingletonRepo(root any, steps []locStep) (repo string, ok bool) {
	if len(steps) == 0 {
		return "", false
	}
	repoPath := steps[:len(steps)-1] // drop the terminal full_name/name → the repo object
	m, ok := walkPath(root, repoPath).(map[string]any)
	if !ok {
		return "", false
	}
	repo = readRepo(m, steps[len(steps)-1:]) // re-read the leaf with one-slash validation
	return repo, repo != ""
}

func walkPath(v any, steps []locStep) any {
	for _, s := range steps {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[s.field]
	}
	return v
}

// ScrubLocations returns the cross-reference content scrub locations for normPath, or nil. A
// scrub location addresses a FOREIGN-repo CONTENT object embedded inside an array element via a
// cross-reference field (e.g. an issue timeline's `cross-referenced` event whose `source.issue`
// is a full issue — title/body — from another, possibly denied, repo). Unlike enum locations
// (which DROP the whole element), a scrub nulls just the cross-ref sub-object when its repo is
// denied and keeps the element, because the array is heterogeneous (most events expose no repo).
func ScrubLocations(normPath string) []string {
	ps := segments(normPath)
	for _, t := range scrubTemplates {
		if t.matches(ps) {
			return t.locs
		}
	}
	return nil
}

// scrubStep is one segment of a scrub location. A '*'-marked field is the cross-ref object NULLED
// when the repo read at the end of the path is denied; the terminal segment names that full_name.
type scrubStep struct {
	field  string
	array  bool
	isNull bool
}

// parseScrubLoc turns "$[].payload.*forkee.full_name" into steps: array, field payload, NULL-target
// field forkee, field full_name. A singleton "$.*parent.full_name" has no array step.
func parseScrubLoc(loc string) []scrubStep {
	var steps []scrubStep
	for _, part := range strings.Split(strings.TrimPrefix(loc, "$"), ".") {
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "[]") {
			if name := strings.TrimSuffix(part, "[]"); name != "" {
				steps = append(steps, scrubStep{field: strings.TrimPrefix(name, "*"), isNull: strings.HasPrefix(name, "*")})
			}
			steps = append(steps, scrubStep{array: true})
			continue
		}
		steps = append(steps, scrubStep{field: strings.TrimPrefix(part, "*"), isNull: strings.HasPrefix(part, "*")})
	}
	return steps
}

// Scrub nulls denied foreign-repo cross-reference content in a response, keeping the enclosing
// row/object. It FAILS CLOSED (ok=false) on a non-empty body it cannot parse, like Redact; an empty
// body passes through. authorized receives "owner/repo". Each location marks (with '*') the field to
// null and gives the path from that field to the foreign repo's full_name; when that repo is present
// and denied the marked field is set to null. Handles both array-element scrubs (e.g. the issue
// timeline's source, an event's payload.forkee) and singleton scrubs (GET /repos/{o}/{r} parent).
func Scrub(body []byte, locs []string, authorized func(ownerRepo string) bool) ([]byte, bool) {
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
		scrubApply(root, parseScrubLoc(loc), authorized)
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

// scrubApply walks a scrub location (which may contain arrays at ANY position), tracking the
// '*'-marked null target's container+key, and nulls that marked sub-object when the repo at the end of
// the path is DENIED. The terminal value is resolved as a one-slash full_name/name OR a repository API
// url (repoFromAPIURL) — so a minimal {id,url,name} cross-ref repo (a check-run's pull_requests head/
// base.repo) is gated by its url. It FAILS CLOSED when the marked cross-ref is present but its repo is
// undeterminable on the primary path (GitHub's `issue` makes the nested `repository` optional while
// `repository_url` is required), scanning the marked sub-object and nulling it on a denied OR
// undeterminable repo — never forwarding an unverifiable foreign cross-ref (round-21).
func scrubApply(cur any, steps []scrubStep, authorized func(string) bool) {
	scrubWalk(cur, steps, nil, "", nil, authorized)
}

func scrubWalk(v any, steps []scrubStep, nullContainer map[string]any, nullKey string, marked any, authorized func(string) bool) {
	if len(steps) == 0 {
		if nullContainer == nil {
			return
		}
		if _, present := nullContainer[nullKey]; !present || marked == nil {
			return
		}
		if repo := repoFromScrubValue(v); repo != "" {
			if !authorized(repo) {
				nullContainer[nullKey] = nil
			}
			return
		}
		scrubFailClosed(nullContainer, nullKey, marked, authorized)
		return
	}
	s := steps[0]
	if s.array {
		if arr, ok := v.([]any); ok {
			for _, el := range arr {
				scrubWalk(el, steps[1:], nullContainer, nullKey, marked, authorized)
			}
		}
		return
	}
	m, ok := v.(map[string]any)
	if !ok {
		// intermediate field missing after the marked cross-ref → terminal unresolvable; fail closed.
		scrubFailClosed(nullContainer, nullKey, marked, authorized)
		return
	}
	nc, nk, mk := nullContainer, nullKey, marked
	if s.isNull {
		nc, nk, mk = m, s.field, m[s.field]
	}
	scrubWalk(m[s.field], steps[1:], nc, nk, mk, authorized)
}

// scrubFailClosed nulls the marked cross-ref (when present) if its repo cannot be determined on the
// primary path: it scans the marked sub-object for any repo identity and nulls on a denied OR
// undeterminable repo.
func scrubFailClosed(nullContainer map[string]any, nullKey string, marked any, authorized func(string) bool) {
	if nullContainer == nil || marked == nil {
		return
	}
	if _, present := nullContainer[nullKey]; !present {
		return
	}
	if denied, found := scanMarkedRepos(marked, authorized); denied || !found {
		nullContainer[nullKey] = nil
	}
}

// repoFromScrubValue resolves a scrub terminal value to "owner/repo": a one-slash full_name/name string,
// or a repository API url (https://api.github.com/repos/{owner}/{repo}[/…]). "" if neither.
func repoFromScrubValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	if strings.Count(s, "/") == 1 {
		return s
	}
	return repoFromAPIURL(s)
}

// scanMarkedRepos walks a marked cross-ref sub-object for repository identities (a full_name property,
// a repository_url API link, or the minimal {id,name,url} event-repo shape — mirroring the Pass-body
// ContainsDeniedRepo scan), reporting whether any is DENIED and whether any was FOUND at all. Used by
// scrubFields to fail closed when the primary `.repository.full_name` path is unresolvable.
func scanMarkedRepos(v any, authorized func(string) bool) (denied, found bool) {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["full_name"].(string); ok && strings.Count(s, "/") == 1 {
			found = true
			if !authorized(s) {
				return true, true
			}
		}
		if u, ok := t["repository_url"].(string); ok {
			if r := repoFromAPIURL(u); r != "" {
				found = true
				if !authorized(r) {
					return true, true
				}
			}
		}
		for _, child := range t {
			d, f := scanMarkedRepos(child, authorized)
			if d {
				return true, true
			}
			found = found || f
		}
	case []any:
		for _, child := range t {
			d, f := scanMarkedRepos(child, authorized)
			if d {
				return true, true
			}
			found = found || f
		}
	}
	return false, found
}
