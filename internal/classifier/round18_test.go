package classifier

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Round-18 B (HIGH): a fan-out fragment DAG (each fragment spreading the next twice, non-cyclic)
// is a tiny query but, without per-walk fragment memoization, drives the classifier's recursive
// walks to 2^N invocations — a single-request CPU-exhaustion DoS reached BEFORE any policy check.
// The visited-fragment guard expands each fragment at most once per walk, so this must classify
// quickly (fail-closed or scoped, either is fine — just not hang).
func TestSec_R18_FragmentFanoutNoDoS(t *testing.T) {
	for _, root := range []string{"query", "mutation"} {
		cond := "Query"
		if root == "mutation" {
			cond = "Mutation"
		}
		const N = 80
		var b strings.Builder
		b.WriteString(`{"query":"` + root + `{ ...f0 }`)
		for i := 0; i < N; i++ {
			if i < N-1 {
				b.WriteString(fmt.Sprintf(" fragment f%d on %s{ ...f%d ...f%d }", i, cond, i+1, i+1))
			} else {
				b.WriteString(fmt.Sprintf(" fragment f%d on %s{ __typename }", i, cond))
			}
		}
		b.WriteString(`"}`)
		body := []byte(b.String())

		done := make(chan struct{}, 1)
		go func() { Classify("POST", "/graphql", body); done <- struct{}{} }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s fragment-fanout (%d bytes) hung >3s — exponential walk DoS", root, len(body))
		}
	}
}

// Round-18 C (HIGH): GitHub's compare basehead accepts a documented triple form `owner:repo:ref`
// referencing an explicit, possibly different-named repository. The classifier must scope that
// foreign repo (the compare body is an unredactable Pass), including when the foreign owner equals
// the path owner — otherwise a denied repo's commits/patches leak.
func TestSec_R18_CompareTripleColonScopes(t *testing.T) {
	has := func(scopes []Scope, owner, repo string) bool {
		for _, s := range scopes {
			if strings.EqualFold(s.Owner, owner) && strings.EqualFold(s.Repo, repo) {
				return true
			}
		}
		return false
	}

	// Same owner, DIFFERENT repo: the side must NOT be dropped just because its owner matches.
	r := Classify(http.MethodGet, "/repos/victim/anyallowed/compare/main...victim:secret-app:main", nil)
	if !has(r.Additional, "victim", "secret-app") {
		t.Fatalf("same-owner triple compare must scope victim/secret-app, got %+v", r.Additional)
	}
	if has(r.Additional, "victim", "anyallowed") {
		t.Fatalf("must not mis-scope the path repo as the foreign repo, got %+v", r.Additional)
	}

	// Different owner AND repo: scope the REAL foreign repo name, not the path repo name.
	r = Classify(http.MethodGet, "/repos/upstream/app/compare/main...other:awesome-app:main", nil)
	if !has(r.Additional, "other", "awesome-app") {
		t.Fatalf("cross-owner triple compare must scope other/awesome-app, got %+v", r.Additional)
	}
	if has(r.Additional, "other", "app") {
		t.Fatalf("must not scope the path repo name for a triple-colon side, got %+v", r.Additional)
	}

	// dependency-graph variant of the triple form.
	r = Classify(http.MethodGet, "/repos/upstream/app/dependency-graph/compare/main...other:awesome-app:main", nil)
	if !has(r.Additional, "other", "awesome-app") {
		t.Fatalf("dependency-graph triple compare must scope other/awesome-app, got %+v", r.Additional)
	}
}

// Round-18 E (MEDIUM): approveDeployments/rejectDeployments act on a workflow run's pending
// deployments — the GraphQL equivalent of POST /actions/runs/{id}/pending_deployments, which REST
// classifies as "actions". They must map to "actions", not "deployments", so an actions="none"
// token cannot un-gate a protected environment over GraphQL.
func TestSec_R18_DeploymentApprovalIsActions(t *testing.T) {
	for _, name := range []string{"approveDeployments", "rejectDeployments"} {
		if got := gqlMutationResource(name); got != "actions" {
			t.Errorf("gqlMutationResource(%q) = %q, want \"actions\"", name, got)
		}
	}
	// A genuine deployments mutation still maps to "deployments".
	if got := gqlMutationResource("createDeployment"); got != "deployments" {
		t.Errorf("gqlMutationResource(createDeployment) = %q, want \"deployments\"", got)
	}
}
