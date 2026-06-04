package classifier

import (
	"net/http"
	"testing"
)

// Round-16 MEDIUM-3: a cross-fork compare (GET /repos/{o}/{r}/compare/{base}...{user}:{head})
// returns the FOREIGN fork's commits/file-patches, which the path-repo scope does not cover and
// restfilter cannot redact. The classifier must emit each foreign owner as an Additional scope so
// the policy denies an un-permitted fork.
func TestCompareForkScopes(t *testing.T) {
	hasScope := func(scopes []Scope, owner, repo string) bool {
		for _, s := range scopes {
			if s.Owner == owner && s.Repo == repo {
				return true
			}
		}
		return false
	}

	t.Run("cross-fork head adds foreign owner scope", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/compare/main...victim:feature", nil)
		if r.Owner != "upstream" || r.Repo != "app" {
			t.Fatalf("primary scope wrong: %+v", r)
		}
		if !hasScope(r.Additional, "victim", "app") {
			t.Fatalf("foreign fork owner 'victim' must be an additional scope, got %+v", r.Additional)
		}
	})

	t.Run("ref containing a slash still extracts the owner", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/compare/main...victim:feature/x", nil)
		if !hasScope(r.Additional, "victim", "app") {
			t.Fatalf("foreign owner must be extracted from a slashed ref, got %+v", r.Additional)
		}
	})

	t.Run("both sides foreign", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/compare/alice:base...bob:head", nil)
		if !hasScope(r.Additional, "alice", "app") || !hasScope(r.Additional, "bob", "app") {
			t.Fatalf("both foreign owners must be scoped, got %+v", r.Additional)
		}
	})

	t.Run("dependency-graph compare variant", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/dependency-graph/compare/main...victim:feature", nil)
		if !hasScope(r.Additional, "victim", "app") {
			t.Fatalf("dependency-graph compare must scope the foreign owner, got %+v", r.Additional)
		}
	})

	t.Run("same-repo compare adds nothing", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/compare/main...dev", nil)
		if len(r.Additional) != 0 {
			t.Fatalf("same-repo compare must add no scope, got %+v", r.Additional)
		}
	})

	t.Run("path owner referenced explicitly is the same repo, not foreign", func(t *testing.T) {
		r := Classify(http.MethodGet, "/repos/upstream/app/compare/upstream:main...upstream:dev", nil)
		if len(r.Additional) != 0 {
			t.Fatalf("path-owner-prefixed refs must add no scope, got %+v", r.Additional)
		}
	})
}
