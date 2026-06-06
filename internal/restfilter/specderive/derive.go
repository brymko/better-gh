// Package specderive derives, from GitHub's OpenAPI description, the data the REST response filter needs
// to locate repositories — the generated drop table (BuildTable, used by internal/restfilter/gen) AND an
// INDEPENDENT over-approximate repo-reachability scan (RepoReach, used by the restfilter spec-coverage
// test). The two derivations are kept deliberately distinct: BuildTable extracts the precise DROP
// locations the runtime uses, while RepoReach conservatively asks "can this response surface a repo at
// all, and is it enumerated / foreign / the path subject?" so the coverage test can catch an op the
// drop-table machinery MISSED (a find() blind spot) rather than only re-confirming what it already found.
package specderive

import (
	"encoding/json"
	"sort"
	"strings"
)

// crossRefFields point to a DIFFERENT repository than the entry's own (a PR's head/base, a fork's
// parent/source, a fork event's forkee, a template). The drop-table must NOT emit locations under them
// (a single-repo endpoint like /pulls would drop legitimate rows whose head is a denied fork); the scrub
// tables handle them instead. Mirrors gqlfilter's crossRepoNavFields.
var crossRefFields = map[string]bool{
	"head": true, "base": true, "forkee": true, "parent": true, "source": true,
	"head_repository": true, "base_repository": true, "template_repository": true,
}

// IsCrossRefField reports whether name is a cross-ref field (head/base/parent/source/template_repository/…)
// — a field under which a repo identity names a DIFFERENT repository than the entry's own. The spec-
// coverage test uses it to assert every FOREIGN location a write response surfaces is matched by a scrub.
func IsCrossRefField(name string) bool { return crossRefFields[name] }

type doc struct {
	Paths      map[string]map[string]operation `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

type operation struct {
	Responses map[string]struct {
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

// Spec is a parsed OpenAPI description plus the derived repo-component set.
type Spec struct {
	d        doc
	schemas  map[string]map[string]any
	repoComp map[string]bool // $ref of a component schema that IS a repository identity (has full_name)
}

// Load parses the bundled api.github.com.json.
func Load(raw []byte) (*Spec, error) {
	var d doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	schemas := map[string]map[string]any{}
	for name, rm := range d.Components.Schemas {
		var m map[string]any
		if json.Unmarshal(rm, &m) == nil {
			schemas[name] = m
		}
	}
	repoComp := map[string]bool{}
	for name, sch := range schemas {
		if props, ok := sch["properties"].(map[string]any); ok {
			if _, ok := props["full_name"]; ok {
				repoComp["#/components/schemas/"+name] = true
			}
		}
	}
	return &Spec{d: d, schemas: schemas, repoComp: repoComp}, nil
}

// Op is one operation.
type Op struct {
	Method string // lowercase
	Path   string
	op     operation
}

// Ops returns every operation in the spec, sorted by "METHOD path" for determinism.
func (s *Spec) Ops() []Op {
	var out []Op
	for path, methods := range s.d.Paths {
		for method, op := range methods {
			out = append(out, Op{Method: method, Path: path, op: op})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func (o Op) respSchema() map[string]any {
	// 202 Accepted is a success body for the async fork-create endpoints (/forks,
	// /security-advisories/{ghsa}/forks) — which echo parent/source/template_repository — so the leak
	// scan must inspect it; without 202 those ops returned a nil schema and were silently skipped
	// (round-22). 200 stays first so a GET's primary response is unchanged.
	for _, code := range []string{"200", "201", "202"} {
		if r, ok := o.op.Responses[code]; ok {
			if c, ok := r.Content["application/json"]; ok && len(c.Schema) > 0 {
				var m map[string]any
				if json.Unmarshal(c.Schema, &m) == nil {
					return m
				}
			}
		}
	}
	return nil
}

// BuildTable produces the generated drop table: repoEnumOps (GET ops → repo-identity JSON locations) and
// knownGetOps (every GET path). This is the SAME derivation the runtime table is generated from.
func (s *Spec) BuildTable() (repoOps map[string][]string, known []string) {
	repoOps = map[string][]string{}
	knownSet := map[string]bool{}
	for _, o := range s.Ops() {
		if o.Method != "get" {
			continue
		}
		key := "GET " + o.Path
		knownSet[key] = true
		schema := o.respSchema()
		if schema == nil {
			continue
		}
		locs := dedupeSort(s.find(schema, "$", map[string]bool{}, 0))
		if len(locs) > 0 {
			repoOps[key] = locs
		}
	}
	for k := range knownSet {
		known = append(known, strings.TrimPrefix(k, "GET "))
	}
	sort.Strings(known)
	return repoOps, known
}

func (s *Spec) deref(m map[string]any, seen map[string]bool, depth int) map[string]any {
	if m == nil || depth > 40 {
		return nil
	}
	if ref, ok := m["$ref"].(string); ok {
		if seen[ref] {
			return nil
		}
		seen[ref] = true
		name := ref[strings.LastIndex(ref, "/")+1:]
		return s.deref(s.schemas[name], seen, depth+1)
	}
	return m
}

func isMinimalRepo(props map[string]any) bool {
	if props == nil {
		return false
	}
	if _, ok := props["full_name"]; ok {
		return false
	}
	_, n := props["name"]
	_, u := props["url"]
	_, id := props["id"]
	return n && u && id && len(props) <= 4
}

// find returns the JSON-paths within a response schema where a repository identity OBJECT appears,
// SKIPPING cross-ref fields (those are scrubbed, not dropped). This is the drop-table derivation.
func (s *Spec) find(m map[string]any, prefix string, seen map[string]bool, depth int) []string {
	if m == nil || depth > 30 {
		return nil
	}
	var out []string
	if ref, ok := m["$ref"].(string); ok && s.repoComp[ref] {
		return []string{prefix + ".full_name"}
	}
	r := s.deref(m, copySet(seen), depth)
	if r == nil {
		return nil
	}
	for _, comp := range []string{"allOf", "oneOf", "anyOf"} {
		if subs, ok := r[comp].([]any); ok {
			for _, sub := range subs {
				if sm, ok := sub.(map[string]any); ok {
					out = append(out, s.find(sm, prefix, copySet(seen), depth+1)...)
				}
			}
		}
	}
	if items, ok := r["items"].(map[string]any); ok {
		out = append(out, s.find(items, prefix+"[]", copySet(seen), depth+1)...)
	}
	props, _ := r["properties"].(map[string]any)
	if _, ok := props["full_name"]; ok && prefix != "$" && !strings.HasSuffix(prefix, "full_name") {
		out = append(out, prefix+".full_name")
	} else if isMinimalRepo(props) && prefix != "$" {
		out = append(out, prefix+".name")
	}
	for name, psch := range props {
		if crossRefFields[name] {
			continue
		}
		if pm, ok := psch.(map[string]any); ok {
			out = append(out, s.find(pm, prefix+"."+name, copySet(seen), depth+1)...)
		}
	}
	return out
}

// RepoReach is the INDEPENDENT over-approximate result for one operation's response: can it surface a
// repository identity, and in what role. It is intentionally NOT derived from find() so the coverage
// test catches find() blind spots.
type RepoReach struct {
	Enum    bool     // a repo identity appears UNDER an array (an enumeration of repos)
	Foreign bool     // a repo identity appears UNDER a cross-ref field (head/base/parent/source/...)
	Subject bool     // a repo identity appears as a non-array, non-cross-ref singleton (the response's subject)
	Paths   []string // role-tagged JSON paths where repo identities were found (for triage/debug)
}

// Any reports whether the response surfaces a repository identity at all.
func (r RepoReach) Any() bool { return r.Enum || r.Foreign || r.Subject }

// RepoReach scans an operation's 2xx response for repository identities and classifies each by role. A
// repo identity is a $ref to a full_name-bearing component, an inline object with a full_name property,
// or the minimal {id,name,url} repo shape — the same shapes the runtime detects, scanned independently.
func (s *Spec) RepoReach(o Op) RepoReach {
	var r RepoReach
	schema := o.respSchema()
	if schema == nil {
		return r
	}
	s.scan(schema, "$", false, false, map[string]bool{}, 0, &r)
	return r
}

func (r *RepoReach) record(path string, underArray, underXRef bool) {
	switch {
	case underXRef:
		r.Foreign = true
		r.Paths = append(r.Paths, "FOREIGN:"+path)
	case underArray:
		r.Enum = true
		r.Paths = append(r.Paths, "ENUM:"+path)
	default:
		r.Subject = true
		r.Paths = append(r.Paths, "SUBJECT:"+path)
	}
}

func (s *Spec) scan(m map[string]any, path string, underArray, underXRef bool, seen map[string]bool, depth int, r *RepoReach) {
	if m == nil || depth > 30 {
		return
	}
	// $ref to a repo component: a repo identity in THIS role (checked before deref so a `seen` cycle on
	// the repo component — e.g. repo.parent.parent — still records the foreign occurrence).
	if ref, ok := m["$ref"].(string); ok && s.repoComp[ref] {
		r.record(path, underArray, underXRef)
	}
	d := s.deref(m, copySet(seen), depth)
	if d == nil {
		return
	}
	props, _ := d["properties"].(map[string]any)
	if depth > 0 {
		if _, ok := props["full_name"]; ok {
			r.record(path, underArray, underXRef)
		} else if isMinimalRepo(props) {
			r.record(path, underArray, underXRef)
		}
	}
	for _, comp := range []string{"allOf", "oneOf", "anyOf"} {
		if subs, ok := d[comp].([]any); ok {
			for _, sub := range subs {
				if sm, ok := sub.(map[string]any); ok {
					s.scan(sm, path, underArray, underXRef, copySet(seen), depth+1, r)
				}
			}
		}
	}
	if items, ok := d["items"].(map[string]any); ok {
		s.scan(items, path+"[]", true, underXRef, copySet(seen), depth+1, r)
	}
	for name, psch := range props {
		if pm, ok := psch.(map[string]any); ok {
			s.scan(pm, path+"."+name, underArray, underXRef || crossRefFields[name], copySet(seen), depth+1, r)
		}
	}
}

// NestsRepoLoc reports whether any drop location nests the repository inside the array element (an
// intermediate field before the terminal, after the last `[]`) rather than the element BEING the repo.
func NestsRepoLoc(locs []string) bool {
	for _, loc := range locs {
		i := strings.LastIndex(loc, "[]")
		if i < 0 {
			continue
		}
		segs := 0
		for _, s := range strings.Split(loc[i+2:], ".") {
			if s != "" {
				segs++
			}
		}
		if segs >= 2 {
			return true
		}
	}
	return false
}

func dedupeSort(in []string) []string {
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func copySet(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
