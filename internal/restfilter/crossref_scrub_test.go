package restfilter

import (
	"strings"
	"testing"
)

// Regression for audit F2 (HIGH): the issue timeline embeds a `cross-referenced` event whose
// source.issue is a FULL issue (title+body) in another, possibly denied, repo. Scrub must null
// the source wrapper of a denied cross-ref while keeping the event, and leave allowed cross-refs
// and ordinary (no-source) events untouched. Dropping the element (the enum path) is wrong here.
func TestScrub_TimelineCrossRef(t *testing.T) {
	body := `[` +
		`{"event":"labeled","label":{"name":"bug"}},` +
		`{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"DENIED_TITLE","body":"DENIED_BODY","repository":{"full_name":"acme/secret"}}}},` +
		`{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"OK_TITLE","body":"OK_BODY","repository":{"full_name":"acme/public"}}}},` +
		`{"event":"commented","body":"a normal comment"}` +
		`]`

	allow := func(repo string) bool { return repo == "acme/public" }
	out, ok := Scrub([]byte(body), []string{"$[].*source.issue.repository.full_name"}, allow)
	if !ok {
		t.Fatal("Scrub returned not-ok on valid body")
	}
	s := string(out)

	if strings.Contains(s, "DENIED_BODY") || strings.Contains(s, "DENIED_TITLE") || strings.Contains(s, "acme/secret") {
		t.Fatalf("denied cross-ref content not scrubbed: %s", s)
	}
	if !strings.Contains(s, "OK_BODY") {
		t.Fatalf("allowed cross-ref content was wrongly scrubbed: %s", s)
	}
	// All four events must survive (scrub nulls the sub-object, never drops the element).
	if got := strings.Count(s, `"event"`); got != 4 {
		t.Fatalf("expected all 4 events kept, got %d: %s", got, s)
	}
	if !strings.Contains(s, `"labeled"`) || !strings.Contains(s, `"commented"`) || !strings.Contains(s, "a normal comment") {
		t.Fatalf("ordinary events were altered: %s", s)
	}
	if !strings.Contains(s, `"source":null`) {
		t.Fatalf("denied cross-ref source should be nulled in place: %s", s)
	}
}

// The timeline endpoint must resolve to scrub locations (it is Pass for the enum table, so the
// scrub table is what closes the leak), and Lookup must still report it Pass (not a repo-bearing
// enum op) so we don't wrongly element-drop it.
func TestScrub_TimelineLookupWiring(t *testing.T) {
	const p = "/repos/acme/public/issues/1/timeline"
	locs := ScrubLocations(p)
	if len(locs) != 1 || locs[0] != "$[].*source.issue.repository.full_name" {
		t.Fatalf("timeline scrub location missing/wrong: %v", locs)
	}
	if d, _ := Lookup(p); d != Pass {
		t.Fatalf("timeline should be Pass for the enum table (scrub handles it), got %v", d)
	}
}

// Regression for round-17 (HIGH): a pull request embeds head.repo / base.repo as FULL Repository
// objects; a PR opened from a (private) fork carries the fork's full_name there. The /pulls
// endpoints are repo-path-scoped Pass (the generator skips head/base), so without a scrub entry the
// denied fork's metadata streamed unredacted. Scrub must null head.repo / base.repo when its repo is
// denied, while keeping the PR row and any allowed base.repo, on both the list and singleton forms.
func TestScrub_PullRequestHeadBaseFork(t *testing.T) {
	allow := func(repo string) bool { return repo == "acme/app" } // the path repo; the fork is denied

	// List form: GET /repos/acme/app/pulls
	list := `[` +
		`{"number":42,"title":"feat","head":{"ref":"f","repo":{"full_name":"secret-team/app","private":true,"description":"FORK_SECRET_DESC"}},"base":{"ref":"main","repo":{"full_name":"acme/app"}}},` +
		`{"number":7,"title":"internal","head":{"ref":"g","repo":{"full_name":"acme/app"}},"base":{"ref":"main","repo":{"full_name":"acme/app"}}}` +
		`]`
	locs := ScrubLocations("/repos/acme/app/pulls")
	if len(locs) == 0 {
		t.Fatal("no scrub locations for GET /repos/{owner}/{repo}/pulls")
	}
	if d, _ := Lookup("/repos/acme/app/pulls"); d != Pass {
		t.Fatalf("/pulls should be Pass (scrub handles head/base), got %v", d)
	}
	out, ok := Scrub([]byte(list), locs, allow)
	if !ok {
		t.Fatal("Scrub returned not-ok on valid /pulls body")
	}
	s := string(out)
	if strings.Contains(s, "secret-team/app") || strings.Contains(s, "FORK_SECRET_DESC") {
		t.Fatalf("denied fork head.repo not scrubbed: %s", s)
	}
	if !strings.Contains(s, `"acme/app"`) {
		t.Fatalf("allowed base.repo wrongly removed: %s", s)
	}
	if c := strings.Count(s, `"number"`); c != 2 {
		t.Fatalf("scrub must keep both PR rows, got %d: %s", c, s)
	}
	if !strings.Contains(s, `"repo":null`) {
		t.Fatalf("denied head.repo should be nulled in place: %s", s)
	}

	// Singleton form: GET /repos/acme/app/pulls/{pull_number}
	one := `{"number":42,"title":"feat","head":{"ref":"f","repo":{"full_name":"secret-team/app","description":"FORK_SECRET_DESC"}},"base":{"ref":"main","repo":{"full_name":"acme/app"}}}`
	slocs := ScrubLocations("/repos/acme/app/pulls/42")
	if len(slocs) == 0 {
		t.Fatal("no scrub locations for GET /repos/{owner}/{repo}/pulls/{pull_number}")
	}
	sout, ok := Scrub([]byte(one), slocs, allow)
	if !ok {
		t.Fatal("Scrub returned not-ok on valid /pulls/{n} body")
	}
	if ss := string(sout); strings.Contains(ss, "secret-team/app") || strings.Contains(ss, "FORK_SECRET_DESC") {
		t.Fatalf("denied fork head.repo not scrubbed on singleton: %s", ss)
	}

	// commits/{sha}/pulls is the third (list) form.
	if len(ScrubLocations("/repos/acme/app/commits/deadbeef/pulls")) == 0 {
		t.Fatal("no scrub locations for GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls")
	}
}

// A non-cross-ref event array with no source must pass through untouched, and an unparseable body
// must fail closed.
func TestScrub_NoSourceAndFailClosed(t *testing.T) {
	clean := `[{"event":"labeled"},{"event":"closed"}]`
	out, ok := Scrub([]byte(clean), []string{"$[].*source.issue.repository.full_name"}, func(string) bool { return false })
	if !ok || strings.Contains(string(out), "null") {
		t.Fatalf("no-source events should be untouched: ok=%v out=%s", ok, out)
	}
	if _, ok := Scrub([]byte("not json"), []string{"$[].*source.issue.repository.full_name"}, func(string) bool { return true }); ok {
		t.Fatal("unparseable body must fail closed (ok=false)")
	}
}
