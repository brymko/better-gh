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
