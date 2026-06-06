package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R33_CopilotMetricsDeniedRepoName: org Copilot metrics name a repo only by a bare `name`
// (no full_name/id/url) nested under copilot_dotcom_pull_requests.repositories[], a shape the Pass
// body-scan can't see; the denied repo's name+usage must be dropped, the allowed kept (round-33).
func TestSec_R33_CopilotMetricsDeniedRepoName(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "acme/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"date":"2026-01-01","copilot_dotcom_pull_requests":{"repositories":[`+
			`{"name":"secret","total_engaged_users":4,"models":[{"name":"gpt"}]},{"name":"public-ok","total_engaged_users":2}]}}]`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, p := range []string{"/orgs/acme/copilot/metrics", "/orgs/acme/team/eng/copilot/metrics"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), `"secret"`) {
			t.Errorf("%s: denied private repo name leaked: %s", p, b)
		}
		if !strings.Contains(string(b), "public-ok") {
			t.Errorf("%s: allowed repo wrongly dropped: %s", p, b)
		}
	}
}
