package restfilter

import (
	"strings"
	"testing"
)

func TestR21_EnumContentResourceEvents(t *testing.T) {
	for _, p := range []string{"/orgs/acme/events", "/repos/o/r/events", "/users/u/events", "/events"} {
		if got := EnumContentResource(p); got != "issues" {
			t.Errorf("EnumContentResource(%q) = %q, want issues", p, got)
		}
	}
}

func TestR21_WriteScrubRequestedReviewers(t *testing.T) {
	if locs := WriteScrubLocations("/repos/o/r/pulls/42/requested_reviewers"); len(locs) == 0 {
		t.Errorf("requested_reviewers must have write-scrub locations (PR head/base.repo)")
	}
}

// Round-21: the cross-ref scrub must fail CLOSED on the repository-omitted shape (only repository_url),
// nulling the cross-ref when its repo is denied or undeterminable — and keep it when allowed.
func TestR21_CrossRefScrubFailClosedOnRepositoryUrlOnly(t *testing.T) {
	loc := []string{"$[].*source.issue.repository.full_name"}

	// source.issue carries only repository_url (no nested repository) → denied → must be nulled.
	denied := `[{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"DENIED_TITLE",` +
		`"body":"db","repository_url":"https://api.github.com/repos/victim/secret"}}}]`
	out, ok := Scrub([]byte(denied), loc, func(r string) bool { return r != "victim/secret" })
	if !ok {
		t.Fatal("Scrub returned not-ok on a valid body")
	}
	if strings.Contains(string(out), "DENIED_TITLE") || strings.Contains(string(out), "victim/secret") {
		t.Fatalf("repository_url-only cross-ref to a denied repo leaked: %s", out)
	}

	// allowed repository_url → cross-ref kept.
	allowed := `[{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"OK_TITLE",` +
		`"repository_url":"https://api.github.com/repos/acme/pub"}}}]`
	out2, ok := Scrub([]byte(allowed), loc, func(r string) bool { return r != "victim/secret" })
	if !ok {
		t.Fatal("Scrub returned not-ok on a valid body")
	}
	if !strings.Contains(string(out2), "OK_TITLE") {
		t.Fatalf("allowed cross-ref wrongly scrubbed: %s", out2)
	}

	// present cross-ref with NO determinable repo → fail closed (nulled).
	norepo := `[{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"INDET_TITLE"}}}]`
	out3, _ := Scrub([]byte(norepo), loc, func(r string) bool { return true })
	if strings.Contains(string(out3), "INDET_TITLE") {
		t.Fatalf("undeterminable cross-ref must fail closed (be nulled): %s", out3)
	}
}

// Round-21: a nested skip-bucket's sibling repository_count must be decremented when denied repos are
// dropped, so it cannot serve as a count oracle.
func TestR21_NestedBucketCountDecremented(t *testing.T) {
	body := `{"skipped_repositories":{"access_mismatch_repos":{"repository_count":2,` +
		`"repositories":[{"full_name":"acme/pub"},{"full_name":"acme/secret"}]}}}`
	locs := []string{"$.skipped_repositories.access_mismatch_repos.repositories[].full_name"}
	out, ok := Redact([]byte(body), locs, func(r string) bool { return r != "acme/secret" })
	if !ok {
		t.Fatal("Redact not-ok")
	}
	s := string(out)
	if strings.Contains(s, "acme/secret") {
		t.Fatalf("denied repo not dropped: %s", s)
	}
	if !strings.Contains(s, `"repository_count":1`) {
		t.Fatalf("nested repository_count not decremented (count oracle): %s", s)
	}
}
