package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// Round-21 HIGH: the activity-event feeds (/orgs/{org}/events, /repos/{o}/{r}/events, …) must enforce
// the issues per-resource carve-out like /orgs/{org}/issues — they were missed from contentEnumResourceOps
// so a base=read + issues=none repo leaked its issue title/body through the events payload.
func TestSec_R21_EventFeedsPerResourceDeny(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{{
			Name: "acme/secret", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"issues": policy.AccessNone},
		}},
	}
	feed := `[{"type":"IssuesEvent","repo":{"id":1,"name":"acme/secret","url":"https://x"},` +
		`"payload":{"issue":{"title":"SECRET_ISSUE_TITLE","body":"sb","repository":{"full_name":"acme/secret"}}}},` +
		`{"type":"IssuesEvent","repo":{"id":2,"name":"acme/open","url":"https://y"},` +
		`"payload":{"issue":{"title":"OK_ISSUE","body":"ob","repository":{"full_name":"acme/open"}}}}]`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, feed)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/orgs/acme/events")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/orgs/acme/events expected 200, got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "SECRET_ISSUE_TITLE") || strings.Contains(s, "acme/secret") {
		t.Fatalf("events feed leaked issues=none repo content: %s", s)
	}
	if !strings.Contains(s, "OK_ISSUE") {
		t.Fatalf("allowed repo's event wrongly dropped: %s", s)
	}
}

// Round-21 MEDIUM: POST/DELETE .../pulls/{n}/requested_reviewers return the full PR (head.repo of a
// fork) and must be scrubbed on the WRITE like PATCH /pulls/{n} — the round-20 write-scrub table missed
// this deeper PR sub-resource.
func TestSec_R21_RequestedReviewersWriteScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "acme/app", Access: policy.AccessReadWrite,
			Permissions: map[string]policy.Access{"pulls": policy.AccessReadWrite},
		}},
	}
	prBody := `{"title":"PR_TITLE","number":42,` +
		`"head":{"ref":"f","repo":{"full_name":"secretteam/fork","private":true}},` +
		`"base":{"ref":"main","repo":{"full_name":"acme/app"}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, prBody)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		req, _ := http.NewRequest(method, srv.URL+"/repos/acme/app/pulls/42/requested_reviewers", strings.NewReader(`{"reviewers":["x"]}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s := string(b)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s requested_reviewers expected 200, got %d: %s", method, resp.StatusCode, s)
		}
		if strings.Contains(s, "secretteam/fork") || strings.Contains(s, "secretteam") {
			t.Fatalf("%s requested_reviewers leaked denied fork head.repo: %s", method, s)
		}
		if !strings.Contains(s, "PR_TITLE") {
			t.Fatalf("%s requested_reviewers over-scrubbed the PR: %s", method, s)
		}
	}
}

// Round-21 MEDIUM: the GraphQL enterprise(slug:) root must be policy-checked (scoped to the slug as an
// org) so an [[org]] deny gates it, instead of falling to Defaults.Mode and leaking enterprise
// owner-private data under default=allow.
func TestSec_R21_EnterpriseRootScoped(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Org:      []policy.OrgRule{{Name: "victim-ent", Access: policy.AccessNone}},
	}
	h := r15Handler(t, pol, "http://127.0.0.1:0") // front-gate deny — never forwarded
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp := postGQL(t, srv.URL, `{ enterprise(slug:"victim-ent"){ billingEmail members(first:10){ nodes{ ... on User { login email } } } } }`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enterprise(slug) under [[org]] victim-ent=none must be 403, got %d", resp.StatusCode)
	}
}

// Round-21 MEDIUM: node(id:Gist) must fail closed (gists is owner-private) so it cannot bypass a gists
// carve-out under default=allow.
func TestSec_R21_NodeGistFailsClosed(t *testing.T) {
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"nodes":[{"__typename":"Gist"}]}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp := postGQL(t, srv.URL, `{ node(id:"G_kwDOABCDEF"){ ... on Gist { description files { text } } } }`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("node(id:Gist) must fail closed under default=allow, got %d", resp.StatusCode)
	}
}

// Round-21 HIGH (buried): a RepositoryMigration reached via repository(){owner{...on Organization{
// repositoryMigrations}}} sits under the OUTER repo's marker; its bare repositoryName names a DIFFERENT
// repo, so the round-20 ambient attribution misattributed it to the allowed outer repo and leaked a
// denied repo's name/log. It must be redacted unconditionally.
func TestSec_R21_RepositoryMigrationAmbientRedacted(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/pub", Access: policy.AccessRead}},
	}
	// Faithful upstream echoing the markers augment injects: repo marker on repository, type marker on
	// the RepositoryMigration node (bare repositoryName).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{`+
			`"bghRepoTagZ9":"acme/pub","bghRepoTypeZ9":"Repository",`+
			`"owner":{"repositoryMigrations":{"nodes":[`+
			`{"repositoryName":"SECRET_MIG_REPO","migrationLogUrl":"https://x/secretlog","bghRepoTypeZ9":"RepositoryMigration"}`+
			`]}}}}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp := postGQL(t, srv.URL, `{ repository(owner:"acme",name:"pub"){ owner{ ... on Organization { repositoryMigrations(first:10){ nodes{ repositoryName } } } } } }`)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (filtered), got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "SECRET_MIG_REPO") || strings.Contains(s, "secretlog") {
		t.Fatalf("RepositoryMigration leaked a denied repo's name/metadata under an allowed repo ancestor: %s", s)
	}
}

// Round-21 (surfaced by the content-feed coverage invariant): two path-scoped content feeds whose
// classifier resource degenerated. /repos/{o}/{r}/commits/{ref}/check-suites is under a /commits/ path
// (classifier "commits") but exposes CHECK data → must gate on "checks"; /repos/{o}/{r}/notifications is
// ResourceUnknown → degenerated to base → must gate on "issues".
func TestSec_R21_PathScopedContentFeedGates(t *testing.T) {
	checkPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "acme/app", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"checks": policy.AccessNone},
		}},
	}
	notifPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "acme/app", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"issues": policy.AccessNone},
		}},
	}
	cases := []struct {
		name, path, body, secret string
		pol                      *policy.Policy
	}{
		{"check-suites checks=none", "/repos/acme/app/commits/main/check-suites",
			`{"total_count":1,"check_suites":[{"id":9,"conclusion":"SECRET_CHECK","repository":{"full_name":"acme/app"}}]}`,
			"SECRET_CHECK", checkPol},
		{"repo notifications issues=none", "/repos/acme/app/notifications",
			`[{"id":"1","subject":{"title":"SECRET_NOTIF"},"repository":{"full_name":"acme/app"}}]`,
			"SECRET_NOTIF", notifPol},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, c.body)
			}))
			defer upstream.Close()
			h := r15Handler(t, c.pol, upstream.URL)
			srv := httptest.NewServer(h)
			defer srv.Close()
			resp, err := http.Get(srv.URL + c.path)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s expected 200, got %d: %s", c.name, resp.StatusCode, b)
			}
			if strings.Contains(string(b), c.secret) {
				t.Fatalf("%s leaked content the per-resource carve-out denies: %s", c.name, b)
			}
		})
	}
}

// Round-21 (surfaced by the spec-coverage test): a check-run's pull_requests[].head.repo (a minimal
// {id,url,name} repo of a fork PR) must be scrubbed via its url when the fork is denied.
func TestSec_R21_CheckRunForkScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/app", Access: policy.AccessRead}},
	}
	body := `{"id":1,"pull_requests":[{"number":7,` +
		`"head":{"ref":"f","repo":{"id":9,"name":"fork","url":"https://api.github.com/repos/victim/secretfork"}},` +
		`"base":{"ref":"main","repo":{"id":2,"name":"app","url":"https://api.github.com/repos/acme/app"}}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/repos/acme/app/check-runs/1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); strings.Contains(s, "secretfork") {
		t.Fatalf("check-run leaked a denied fork's head.repo: %s", s)
	}
}

// Round-21: a codespace WRITE response (PATCH) exposes `repository` (the codespace's repo) which the
// write path doesn't redact — null it when the repo is denied (a user-write + per-repo-none bypass).
func TestSec_R21_CodespaceWriteRepoScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessReadWrite}},
		Repo:     []policy.RepoRule{{Name: "victim/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"name":"cs1","repository":{"full_name":"victim/secret","private":true,"description":"SECRET_DESC"}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/user/codespaces/cs1", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); strings.Contains(s, "victim/secret") || strings.Contains(s, "SECRET_DESC") {
		t.Fatalf("codespace write leaked the denied repository: %s", s)
	}
}

// Round-21: adding a denied repo's issue to a project (POST projectsV2 items) must null the linked
// `content` — a REST sidedoor around the node(id:) content-read block.
func TestSec_R21_ProjectItemContentScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessReadWrite}},
		Repo:     []policy.RepoRule{{Name: "victim/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":5,"content":{"title":"SECRET_ISSUE","body":"sb","repository":{"full_name":"victim/secret"}}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/orgs/acme/projectsV2/1/items", strings.NewReader(`{"content_id":1,"content_type":"Issue"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "victim/secret") {
		t.Fatalf("project-item-add leaked a denied repo's issue content: %s", s)
	}
}
