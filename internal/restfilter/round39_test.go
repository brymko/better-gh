package restfilter

import "testing"

// TestR39_WebURLRepoScan pins the round-39 finding-7 fix: the Pass body-scan recognizes a github.com WEB url
// naming a repo (the Classroom /assignments/{id}/grades student_repository_url html_url shape), value-driven
// so it covers *_url siblings — while NOT over-matching an api.github.com link or a reserved path.
func TestR39_WebURLRepoScan(t *testing.T) {
	deny := func(ownerRepo string) bool { return ownerRepo != "classroom-org/intro-alice" }

	// the Classroom grades shape: an array of {github_username, student_repository_name, student_repository_url}.
	body := []byte(`[{"github_username":"alice","student_repository_name":"intro-alice",` +
		`"student_repository_url":"https://github.com/classroom-org/intro-alice","grade":"100"}]`)
	denied, ok := ContainsDeniedRepo(body, "", deny)
	if !ok {
		t.Fatal("grades body failed to parse")
	}
	if !denied {
		t.Fatalf("denied student repo (student_repository_url html_url) not detected — leak forwarded")
	}

	// an ALLOWED student repo must NOT trip the scan.
	okBody := []byte(`[{"student_repository_url":"https://github.com/classroom-org/intro-bob"}]`)
	if d, _ := ContainsDeniedRepo(okBody, "", deny); d {
		t.Fatalf("allowed student repo url wrongly flagged")
	}

	// must NOT over-match: a reserved github.com path, a 1-segment profile, or a foreign host (a denied repo
	// via api.github.com is still caught by the repository_url keyed check, not this web-url path).
	for _, b := range []string{
		`{"x":"https://github.com/orgs/classroom-org/teams/secret"}`,
		`{"x":"https://github.com/classroom-org"}`,
		`{"x":"https://example.com/classroom-org/intro-alice"}`,
	} {
		if d, _ := ContainsDeniedRepo([]byte(b), "", deny); d {
			t.Errorf("web-url scan over-matched a non-repo/reserved/foreign-host url: %s", b)
		}
	}
}
