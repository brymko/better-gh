// Command gen derives, from GitHub's OpenAPI description, the table the REST response filter
// uses to locate repositories in each endpoint's response — so coverage is mechanical (the whole
// REST surface) and fail-closed, not a hand-maintained allowlist.
//
// Usage:
//
//	go run ./internal/restfilter/gen --spec <api.github.com.json> --out internal/restfilter/openapi_table.go
//
// Fetch the spec from:
//
//	https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

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

func main() {
	specPath := flag.String("spec", "", "path to api.github.com.json")
	out := flag.String("out", "", "output Go file")
	flag.Parse()
	if *specPath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: gen --spec <spec.json> --out <file.go>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*specPath)
	must(err)
	var d doc
	must(json.Unmarshal(raw, &d))

	schemas := map[string]map[string]any{}
	for name, rm := range d.Components.Schemas {
		var m map[string]any
		if json.Unmarshal(rm, &m) == nil {
			schemas[name] = m
		}
	}

	// A schema is a repository identity if it has a string `full_name` property.
	repoComp := map[string]bool{}
	for name, sch := range schemas {
		if props, ok := sch["properties"].(map[string]any); ok {
			if _, ok := props["full_name"]; ok {
				repoComp["#/components/schemas/"+name] = true
			}
		}
	}

	g := &generator{schemas: schemas, repoComp: repoComp}

	repoOps := map[string][]string{}
	known := map[string]bool{}
	for path, methods := range d.Paths {
		for method, op := range methods {
			if method != "get" { // reads are the enumeration/leak surface; writes are repo-gated by the classifier
				continue
			}
			key := "GET " + path
			known[key] = true
			schema := resp200JSON(op)
			if schema == nil {
				continue
			}
			locs := g.find(schema, "$", map[string]bool{}, 0)
			locs = dedupeSort(locs)
			if len(locs) > 0 {
				repoOps[key] = locs
			}
		}
	}

	emit(*out, repoOps, known)
	fmt.Fprintf(os.Stderr, "gen: %d GET ops, %d repo-bearing\n", len(known), len(repoOps))
}

type generator struct {
	schemas  map[string]map[string]any
	repoComp map[string]bool
}

// crossRefFields point to a DIFFERENT repository than the entry's own (a PR's head/base, a
// fork's parent/source, a fork event's forkee, a template). We must NOT emit locations under
// them, or a single-repo endpoint like /repos/{o}/{r}/pulls would drop legitimate entries whose
// head/base happens to be a denied fork. Mirrors gqlfilter's crossRepoNavFields.
var crossRefFields = map[string]bool{
	"head": true, "base": true, "forkee": true, "parent": true, "source": true,
	"head_repository": true, "base_repository": true, "template_repository": true,
}

// isMinimalRepo reports whether props is the inline {id,name,url} shape GitHub uses for a
// repository in event/timeline payloads (name = "owner/repo", no full_name). The runtime
// re-validates the one-slash shape, so this only needs to be approximately right.
func isMinimalRepo(props map[string]any) bool {
	if _, ok := props["full_name"]; ok {
		return false
	}
	_, n := props["name"]
	_, u := props["url"]
	_, id := props["id"]
	return n && u && id && len(props) <= 4
}

func (g *generator) deref(s map[string]any, seen map[string]bool, depth int) map[string]any {
	if depth > 40 {
		return nil
	}
	if ref, ok := s["$ref"].(string); ok {
		if seen[ref] {
			return nil
		}
		seen[ref] = true
		name := ref[strings.LastIndex(ref, "/")+1:]
		return g.deref(g.schemas[name], seen, depth+1)
	}
	return s
}

// find returns the JSON-paths within a (possibly $ref'd) response schema where a repository
// identity object appears, e.g. "$[].repository.full_name" or "$.repositories[].full_name".
func (g *generator) find(s map[string]any, prefix string, seen map[string]bool, depth int) []string {
	if s == nil || depth > 30 {
		return nil
	}
	var out []string
	if ref, ok := s["$ref"].(string); ok {
		if g.repoComp[ref] {
			return []string{prefix + ".full_name"}
		}
	}
	r := g.deref(s, copySet(seen), depth)
	if r == nil {
		return nil
	}
	for _, comp := range []string{"allOf", "oneOf", "anyOf"} {
		if subs, ok := r[comp].([]any); ok {
			for _, sub := range subs {
				if sm, ok := sub.(map[string]any); ok {
					out = append(out, g.find(sm, prefix, copySet(seen), depth+1)...)
				}
			}
		}
	}
	if items, ok := r["items"].(map[string]any); ok {
		out = append(out, g.find(items, prefix+"[]", copySet(seen), depth+1)...)
	}
	props, _ := r["properties"].(map[string]any)
	// Is this object itself a repository identity?
	if _, ok := props["full_name"]; ok && prefix != "$" && !strings.HasSuffix(prefix, "full_name") {
		out = append(out, prefix+".full_name")
	} else if isMinimalRepo(props) && prefix != "$" {
		out = append(out, prefix+".name") // event/timeline {id,name,url} repo shape
	}
	for name, psch := range props {
		if crossRefFields[name] {
			continue // a different repo than this entry's own — don't redact the entry against it
		}
		if pm, ok := psch.(map[string]any); ok {
			out = append(out, g.find(pm, prefix+"."+name, copySet(seen), depth+1)...)
		}
	}
	return out
}

func resp200JSON(op operation) map[string]any {
	for _, code := range []string{"200", "201"} {
		if r, ok := op.Responses[code]; ok {
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

func emit(path string, repoOps map[string][]string, known map[string]bool) {
	var b strings.Builder
	b.WriteString("// Code generated from GitHub's OpenAPI description by internal/restfilter/gen. DO NOT EDIT.\n")
	b.WriteString("// Regenerate: go run ./internal/restfilter/gen --spec api.github.com.json --out internal/restfilter/openapi_table.go\n\n")
	b.WriteString("package restfilter\n\n")
	b.WriteString("// repoEnumOps maps \"GET /path/{tmpl}\" to the JSON locations of repository identities in\n")
	b.WriteString("// its response, so the filter can drop denied-repo data wherever it appears.\n")
	b.WriteString("var repoEnumOps = map[string][]string{\n")
	for _, k := range sortedKeys(repoOps) {
		b.WriteString(fmt.Sprintf("\t%q: {", k))
		for i, l := range repoOps[k] {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fmt.Sprintf("%q", l))
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n")
	b.WriteString("// knownGetOps is every GET path template in the spec. A GET whose path matches none of\n")
	b.WriteString("// these is off-spec and the filter fails closed (the spec is comprehensive).\n")
	b.WriteString("var knownGetOps = []string{\n")
	for _, k := range sortedBoolKeys(known) {
		b.WriteString(fmt.Sprintf("\t%q,\n", strings.TrimPrefix(k, "GET ")))
	}
	b.WriteString("}\n")
	must(os.WriteFile(path, []byte(b.String()), 0o644))
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
func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
