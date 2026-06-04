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
	enumTemplates  []opTemplate // repo-bearing GET ops (Redact)
	knownTemplates []opTemplate // every GET op (to tell Pass from Unknown)
)

func init() {
	for key, locs := range repoEnumOps {
		enumTemplates = append(enumTemplates, parseTemplate(strings.TrimPrefix(key, "GET "), locs))
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
	root = applyLocations(root, locs, authorized)
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
			root = nullSingleton(root, steps, authorized)
			continue
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

// nullSingleton handles a repo with no enclosing array (e.g. $.repository.full_name): null the
// repo object in its parent when its repo is denied or undeterminable.
func nullSingleton(root any, steps []locStep, authorized func(string) bool) any {
	repoPath := steps[:len(steps)-1] // drop the terminal full_name/name → the repo object
	obj := walkPath(root, repoPath)
	m, ok := obj.(map[string]any)
	if !ok {
		return root
	}
	fn := readRepo(m, steps[len(steps)-1:]) // re-read the leaf with one-slash validation
	if fn != "" && authorized(fn) {
		return root
	}
	if len(repoPath) == 0 {
		return nil // root itself is the repo object
	}
	parent := walkPath(root, repoPath[:len(repoPath)-1])
	if pm, ok := parent.(map[string]any); ok {
		pm[repoPath[len(repoPath)-1].field] = nil
	}
	return root
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
