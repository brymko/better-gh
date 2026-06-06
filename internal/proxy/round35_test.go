package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R35_UsersPathPrivateSubtreeDenied: the documented `[[org]] name="<custodian-login>"` read grant
// (for `gh repo list <login>`) must NOT expose the custodian's authenticated-only /users/{login}/* subtrees
// — /users/<login>/settings/billing/* (private billing) and /users/<login>/projectsV2 (private projects).
// They classify to the un-floored user_private category and are denied; the public /users/<login>/repos feed
// stays allowed under the org grant (round-35 finding-1).
func TestSec_R35_UsersPathPrivateSubtreeDenied(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "octocat", Access: policy.AccessRead}},
	}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"usageItems":[{"product":"actions","netAmount":12.34,"BILLING_SECRET":"private"}]}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, p := range []string{
		"/users/octocat/settings/billing/usage",
		"/users/octocat/settings/billing/usage/summary",
		"/users/octocat/projectsV2",
		"/users/octocat/docker/conflicts",
	} {
		hit = false
		resp, _ := http.Get(srv.URL + p)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: custodian-private subtree not denied (status %d): %s", p, resp.StatusCode, b)
		}
		if hit {
			t.Errorf("%s: denied custodian-private subtree reached upstream", p)
		}
		if strings.Contains(string(b), "BILLING_SECRET") {
			t.Errorf("%s: custodian billing data leaked: %s", p, b)
		}
	}
	// the public third-person feed must STILL work under the org grant (gh repo list <login>).
	resp, _ := http.Get(srv.URL + "/users/octocat/repos")
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("/users/octocat/repos wrongly denied — the org grant must still enumerate public repos, status %d", resp.StatusCode)
	}
}

// TestSec_R35_CopilotSpacesOpaqueRepoIDFailClosed: a Copilot Space names an attached repo only by a numeric
// repository_id (+ bare name / file_path) nested under resources_attributes[].metadata — a shape neither the
// generator nor the Pass body-scan can map — so the op must FAIL CLOSED rather than forward a denied repo's
// id/existence (round-35 finding-3, the opaque-numeric-id class).
func TestSec_R35_CopilotSpacesOpaqueRepoIDFailClosed(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "acme/secret-repo", Access: policy.AccessNone}},
	}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"number":1,"name":"sp","resources_attributes":[{"type":"repository","metadata":`+
			`{"repository_id":424242,"name":"secret-repo","file_path":"src/secret/keys.md"}}]}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, p := range []string{
		"/orgs/acme/copilot-spaces",
		"/orgs/acme/copilot-spaces/1",
		"/orgs/acme/copilot-spaces/1/resources",
	} {
		hit = false
		resp, _ := http.Get(srv.URL + p)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: opaque repository_id op must fail closed, got status %d: %s", p, resp.StatusCode, b)
		}
		if hit {
			t.Errorf("%s: fail-closed op reached upstream", p)
		}
		if strings.Contains(string(b), "424242") || strings.Contains(string(b), "secret-repo") || strings.Contains(string(b), "src/secret") {
			t.Errorf("%s: denied repo's id/name/path leaked via opaque copilot-space metadata: %s", p, b)
		}
	}
}
