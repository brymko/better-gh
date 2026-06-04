package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/policy"
)

// Regression for audit F2 (HIGH) end-to-end: GET /repos/{o}/{r}/issues/{n}/timeline on an ALLOWED
// repo must not leak the title/body of a cross-referenced issue in a DENIED repo. The denied
// source is scrubbed in place (its `source` wrapper nulled) while the event row and unrelated
// events survive.
func TestSec_E2E_TimelineCrossRefScrubbed_F2(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[`+
			`{"event":"labeled","label":{"name":"bug"}},`+
			`{"event":"cross-referenced","source":{"type":"issue","issue":{"title":"DENIED_TITLE","body":"DENIED_SOURCE_BODY","repository":{"full_name":"acme/secret"}}}},`+
			`{"event":"commented","body":"ordinary comment"}`+
			`]`)
	}))
	t.Cleanup(upstream.Close)

	// acme/public allowed (the timeline path repo); acme/secret denied (default deny, unlisted).
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/public", Access: policy.AccessRead}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/repos/acme/public/issues/1/timeline")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("timeline of an allowed repo should be 200 (denied cross-ref scrubbed in-body), got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "DENIED_SOURCE_BODY") || strings.Contains(s, "DENIED_TITLE") || strings.Contains(s, "acme/secret") {
		t.Fatalf("F2 leak: denied repo's cross-referenced issue content forwarded: %s", s)
	}
	if !strings.Contains(s, `"source":null`) {
		t.Fatalf("denied cross-ref source must be nulled in place: %s", s)
	}
	if !strings.Contains(s, "ordinary comment") || !strings.Contains(s, `"labeled"`) {
		t.Fatalf("unrelated timeline events were dropped/altered: %s", s)
	}
}
