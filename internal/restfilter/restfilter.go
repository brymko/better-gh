// Package restfilter redacts denied-repo entries from REST responses.
//
// The GraphQL response filter (internal/gqlfilter) makes cross-repo navigation and enumeration
// safe for GraphQL; this is its REST counterpart. Coverage and the location of each repository
// in a response are DERIVED FROM GitHub's OpenAPI description (see internal/restfilter/gen and
// openapi_table.go), not a hand-maintained allowlist — so the whole REST surface is covered and
// a path the spec doesn't describe can be failed closed by the proxy. For a recognized endpoint
// the filter walks the response to the repository locations the spec gives and drops the denied
// ones (dropping the enclosing list element, or nulling a singleton repo object); on a non-empty
// body it cannot parse it fails closed. See Lookup/Redact in openapi.go.
package restfilter

import "strings"

func segments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// IsRepoEnumPath reports whether a GET to normPath returns repository-bearing entries that must
// be redacted (i.e. the spec gives it repository locations). Single-repo paths the classifier
// already scopes, and endpoints with no repositories, are not enum paths.
func IsRepoEnumPath(normPath string) bool {
	d, _ := Lookup(normPath)
	return d == NeedsFilter
}

// Filter redacts denied-repo data from a recognized GET response. Unrecognized or non-repo
// responses are returned unchanged (the proxy makes the fail-closed decision via Lookup); a
// recognized repo-bearing response that cannot be parsed is also returned unchanged here —
// callers that need fail-closed semantics use Redact directly.
func Filter(normPath string, body []byte, authorized func(ownerRepo string) bool) []byte {
	d, locs := Lookup(normPath)
	if d != NeedsFilter {
		return body
	}
	if out, ok := Redact(body, locs, authorized); ok {
		return out
	}
	return body
}
