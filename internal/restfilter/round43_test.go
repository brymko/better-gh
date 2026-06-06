package restfilter

import (
	"strings"
	"testing"
)

// TestR43_WorkflowRunForeignRepoScrubbed pins round-43 F4: a workflow-run's head_repository (the fork that
// produced a fork-originated run) and its pull_requests[].head/base.repo are nulled when the policy denies
// that fork, while the allowed repos survive.
func TestR43_WorkflowRunForeignRepoScrubbed(t *testing.T) {
	for _, p := range []string{
		"/repos/acme/app/actions/runs/5",
		"/repos/acme/app/actions/runs",
		"/repos/acme/app/check-suites/9",
	} {
		if len(ScrubLocations(p)) == 0 {
			t.Fatalf("no cross-ref scrub locations registered for %s", p)
		}
	}
	locs := ScrubLocations("/repos/acme/app/actions/runs/5")
	body := []byte(`{"id":5,
		"head_repository":{"full_name":"acme/secret-fork","private":true},
		"pull_requests":[
			{"head":{"repo":{"url":"https://api.github.com/repos/acme/secret-fork","name":"secret-fork"}},
			 "base":{"repo":{"url":"https://api.github.com/repos/acme/app","name":"app"}}}]}`)
	authorized := func(or string) bool { return or != "acme/secret-fork" }
	out, ok := Scrub(body, locs, authorized)
	if !ok {
		t.Fatal("scrub failed")
	}
	if strings.Contains(string(out), "secret-fork") {
		t.Fatalf("F4: denied fork head_repository / head.repo not scrubbed: %s", out)
	}
	if !strings.Contains(string(out), "repos/acme/app") {
		t.Fatalf("F4: allowed base.repo wrongly scrubbed: %s", out)
	}
}

// TestR43_RepoKeyedMapRedacted pins round-43 F5: the org Copilot content_exclusion response is a JSON object
// KEYED by repo name; a denied repo's key (+ its file-path globs) is dropped, the allowed repos survive, and
// the op is recognized + fails closed without a qualifying owner.
func TestR43_RepoKeyedMapRedacted(t *testing.T) {
	if !IsRepoKeyedMap("/orgs/acme/copilot/content_exclusion") {
		t.Fatal("content_exclusion not recognized as a repo-keyed map op")
	}
	body := []byte(`{"secret-repo":["/internal/**","/secrets/*"],"public-repo":["/docs/**"]}`)
	authorized := func(or string) bool { return or != "acme/secret-repo" }
	out, ok := RedactRepoKeyedMap(body, "acme", authorized)
	if !ok {
		t.Fatal("redact failed")
	}
	if strings.Contains(string(out), "secret-repo") || strings.Contains(string(out), "/internal/**") {
		t.Fatalf("F5: denied repo KEY (+ its globs) not dropped: %s", out)
	}
	if !strings.Contains(string(out), "public-repo") {
		t.Fatalf("F5: allowed repo key wrongly dropped: %s", out)
	}
	if _, ok := RedactRepoKeyedMap(body, "", authorized); ok {
		t.Fatal("F5: must fail closed without a qualifying owner")
	}
}
