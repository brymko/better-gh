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
// locations. It FAILS CLOSED (ok=false) on a non-empty body it cannot parse — a known
// repo-bearing op returning non-JSON is anomalous and must not be forwarded unredacted. An
// empty body (e.g. a 304) is passed through. authorized receives "owner/repo".
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
	origItems := itemsLen(root)
	// Singleton (non-array) locations address the response's OWN subject repository (a
	// notification thread, a codespace, a single package). If that repo is present and denied,
	// the WHOLE body belongs to a denied repo and its same-repo siblings (issue/PR titles, branch
	// names, source paths) would survive a mere sub-object null — so fail closed and let the proxy
	// reject the body, matching the all-or-nothing semantics the array path gets by dropping the
	// element (audit F4). An absent/undeterminable singleton repo (e.g. an org-scoped package with
	// no repository) exposes no repo identity, so it is not failed. For repo-path-scoped endpoints
	// the singleton repo is the path repo the classifier already authorized, so this never trips.
	var arrayLocs []string
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
		if repo := readSingletonRepo(root, steps); repo != "" && !authorized(repo) {
			return nil, false
		}
	}
	root = applyLocations(root, arrayLocs, authorized)
	// Close the search count oracle: if items were dropped from a {items,total_count} body,
	// rewrite the count and flag it incomplete (same as the old filter did for /search).
	if m, ok := root.(map[string]any); ok && origItems >= 0 {
		if n := itemsLen(root); n < origItems {
			if _, has := m["total_count"]; has {
				m["total_count"] = json.Number(strconv.Itoa(n))
				m["incomplete_results"] = true
			}
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}

func itemsLen(root any) int {
	m, ok := root.(map[string]any)
	if !ok {
		return -1
	}
	items, ok := m["items"].([]any)
	if !ok {
		return -1
	}
	return len(items)
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

// applyLocations redacts denied repositories addressed by all of an endpoint's locations.
// Locations that filter the SAME array are evaluated together per element (an element is kept
// only if it exposes at least one determinable repository and ALL exposed repositories are
// allowed) — so an element isn't dropped merely because one location's optional path is absent
// (e.g. a PushEvent has repo.name but no payload.issue.repository). A singleton repo (no
// enclosing array) is nulled when denied.
func applyLocations(root any, locs []string, authorized func(string) bool) any {
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
	for _, key := range order {
		g := groups[key]
		root = descendGroup(root, g.prefix, g.elems, authorized)
	}
	return root
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
func descendGroup(cur any, prefix []locStep, elems [][]locStep, authorized func(string) bool) any {
	if len(prefix) == 0 {
		arr, ok := cur.([]any)
		if !ok {
			return cur
		}
		kept := make([]any, 0, len(arr))
		for _, el := range arr {
			if elementAllowed(el, elems, authorized) {
				kept = append(kept, el)
			}
		}
		return kept
	}
	s := prefix[0]
	if s.array {
		arr, ok := cur.([]any)
		if !ok {
			return cur
		}
		for i := range arr {
			arr[i] = descendGroup(arr[i], prefix[1:], elems, authorized)
		}
		return arr
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return cur
	}
	if v, present := m[s.field]; present {
		m[s.field] = descendGroup(v, prefix[1:], elems, authorized)
	}
	return cur
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
// $.repository.full_name or $.full_name → the response's own subject repo), or "" if the field
// is absent/malformed. Redact fails the whole body closed when such a repo is present and denied.
func readSingletonRepo(root any, steps []locStep) string {
	repoPath := steps[:len(steps)-1] // drop the terminal full_name/name → the repo object
	m, ok := walkPath(root, repoPath).(map[string]any)
	if !ok {
		return ""
	}
	return readRepo(m, steps[len(steps)-1:]) // re-read the leaf with one-slash validation
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

// scrubApply dispatches an array-rooted scrub (recurse per element on the tail) or a singleton scrub
// (walk fields from the root). Scrub locations always have the array (if any) at the front.
func scrubApply(cur any, steps []scrubStep, authorized func(string) bool) {
	if len(steps) == 0 {
		return
	}
	if steps[0].array {
		arr, ok := cur.([]any)
		if !ok {
			return
		}
		for _, el := range arr {
			scrubFields(el, steps[1:], authorized)
		}
		return
	}
	scrubFields(cur, steps, authorized)
}

// scrubFields walks pure field steps from obj, tracking the '*'-marked null target's container+key
// and reading the repo at the terminal field; it nulls the marked field when that repo is present
// and denied. The surrounding object is otherwise untouched.
func scrubFields(obj any, steps []scrubStep, authorized func(string) bool) {
	var nullContainer map[string]any
	var nullKey string
	v := obj
	for _, s := range steps {
		if s.array {
			return // nested arrays in a scrub path are unsupported (none in the table)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		if s.isNull {
			nullContainer, nullKey = m, s.field
		}
		v = m[s.field]
	}
	repo, _ := v.(string)
	if strings.Count(repo, "/") != 1 {
		return
	}
	if !authorized(repo) && nullContainer != nil {
		if _, present := nullContainer[nullKey]; present {
			nullContainer[nullKey] = nil
		}
	}
}
