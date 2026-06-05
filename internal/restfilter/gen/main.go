// Command gen derives, from GitHub's OpenAPI description, the table the REST response filter uses to
// locate repositories in each endpoint's response — so coverage is mechanical (the whole REST surface)
// and fail-closed, not a hand-maintained allowlist. The derivation lives in internal/restfilter/specderive
// (shared with the restfilter spec-coverage test); this is a thin CLI.
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
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"better-gh/internal/restfilter/specderive"
)

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
	spec, err := specderive.Load(raw)
	must(err)

	repoOps, known := spec.BuildTable()
	emit(*out, repoOps, known)
	fmt.Fprintf(os.Stderr, "gen: %d GET ops, %d repo-bearing\n", len(known), len(repoOps))

	reportCoverage(spec, repoOps)
}

// reportCoverage prints (to stderr) the ops a maintainer must keep covered in the hand-maintained
// restfilter tables after a spec refresh: nests-a-repo GET enum ops (-> content_resource.go) and WRITE
// ops embedding a foreign cross-ref repo (-> write_scrub.go — write responses are invisible to the
// GET-only table, so this report is the only generation-time guard for write-scrub coverage). The runtime
// TestCoverage_NestedRepoEnumOps + TestSpecCoverage_* ENFORCE coverage; this just tells the maintainer
// WHAT to classify.
func reportCoverage(spec *specderive.Spec, repoOps map[string][]string) {
	var content, writeScrub []string
	for key, locs := range repoOps {
		if specderive.NestsRepoLoc(locs) {
			content = append(content, strings.TrimPrefix(key, "GET "))
		}
	}
	for _, o := range spec.Ops() {
		if o.Method == "get" || o.Method == "head" {
			continue
		}
		if spec.RepoReach(o).Foreign {
			writeScrub = append(writeScrub, strings.ToUpper(o.Method)+" "+o.Path)
		}
	}
	sort.Strings(content)
	sort.Strings(writeScrub)
	fmt.Fprintf(os.Stderr, "\ngen: COVERAGE REVIEW — keep these classified in the hand-maintained tables:\n")
	fmt.Fprintf(os.Stderr, "  %d nests-a-repo GET enum ops -> content_resource.go (content key OR metadata allowlist):\n", len(content))
	for _, p := range content {
		fmt.Fprintf(os.Stderr, "    %s\n", p)
	}
	fmt.Fprintf(os.Stderr, "  %d WRITE ops embedding a cross-ref repo -> write_scrub.go (writeScrubOps):\n", len(writeScrub))
	for _, p := range writeScrub {
		fmt.Fprintf(os.Stderr, "    %s\n", p)
	}
}

func emit(path string, repoOps map[string][]string, known []string) {
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
	for _, k := range known {
		b.WriteString(fmt.Sprintf("\t%q,\n", k))
	}
	b.WriteString("}\n")
	must(os.WriteFile(path, []byte(b.String()), 0o644))
}

func sortedKeys(m map[string][]string) []string {
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
