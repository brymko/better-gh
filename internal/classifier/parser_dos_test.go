package classifier

import (
	"strings"
	"testing"
)

// Regression for audit F3 (HIGH): a deeply nested GraphQL query must NOT crash the process.
// gqlparser's recursive-descent parser has no depth guard and parser.ParseQuery uses an
// unlimited token count, so before the fix a nested body (well under the 10MB request cap)
// drove the goroutine stack past Go's 1GB ceiling — a fatal, unrecoverable stack overflow that
// fired in classifyGraphQL BEFORE any policy check. classifyGraphQL now parses with a token
// limit, so the parser fails closed (unwinds) and the over-limit query is treated like any
// unparseable one: an unscoped write, which the policy denies.
func TestSec_GraphQLDeepNestingFailsClosedNoCrash(t *testing.T) {
	// ~300k nesting levels (~900KB) — far below the 10MB body cap, far above the token limit.
	// Without the bound this class of input fatally crashes the process at higher depth; the
	// token limit makes the parser bail near ~50k levels, long before the stack overflows.
	const depth = 300_000
	body := `{"query":"query ` + strings.Repeat("{a", depth) + strings.Repeat("}", depth) + `"}`

	r := Classify("POST", "/graphql", []byte(body))

	// Over-limit parse → fail closed: classifyGraphQL returns an unscoped write (denied by policy),
	// the same as for an unparseable query.
	if r.Access != Write {
		t.Fatalf("deeply nested query must fail closed as a write (denied); got access=%v repo=%q", r.Access, r.RepoFullName())
	}
	if r.HasRepo() || r.Org != "" || r.UnscopedCategory != "" {
		t.Fatalf("over-limit query must carry no allowed scope; got repo=%q org=%q cat=%q", r.RepoFullName(), r.Org, r.UnscopedCategory)
	}
}

// A normal-sized nested query (well under the token limit) must still parse and classify
// normally — the bound must not break legitimate queries.
func TestSec_GraphQLModerateNestingStillClassifies(t *testing.T) {
	body := `{"query":"query { repository(owner:\"o\",name:\"r\") { pullRequests(first:10){ nodes { title } } } }"}`
	r := Classify("POST", "/graphql", []byte(body))
	if r.Access != Read || r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("legitimate query misclassified after token bound: access=%v owner=%q repo=%q", r.Access, r.Owner, r.Repo)
	}
}
