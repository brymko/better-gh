package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R22_ForkTemplateRepoScrub: POST /repos/{o}/{r}/forks returns a 202 full-repository body whose
// template_repository names a private template the client cannot read; the round-20 scrub covered only
// parent/source, so template_repository leaked (round-22). It must now be scrubbed.
func TestSec_R22_ForkTemplateRepoScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/app", Access: policy.AccessReadWrite}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"full_name":"me/myfork","template_repository":{"full_name":"victim/private-template","private":true,"description":"SECRET_TPL"}}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/repos/acme/app/forks", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); strings.Contains(s, "victim/private-template") || strings.Contains(s, "SECRET_TPL") {
		t.Fatalf("fork-create leaked the denied template repository: %s", s)
	}
}

// TestSec_R22_AdvisoryForkScrub: POST /repos/{o}/{r}/security-advisories/{ghsa}/forks returns a 202
// full-repository body; it had NO scrub entry at all (so respFilter stayed nil and the whole body
// streamed). Its template_repository (a denied template) must now be scrubbed (round-22).
func TestSec_R22_AdvisoryForkScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/app", Access: policy.AccessReadWrite}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"full_name":"acme/app-ghsa-fork","template_repository":{"full_name":"victim/private-template","private":true,"description":"SECRET_TPL"}}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/repos/acme/app/security-advisories/GHSA-xxxx-yyyy-zzzz/forks", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); strings.Contains(s, "victim/private-template") || strings.Contains(s, "SECRET_TPL") {
		t.Fatalf("advisory-fork leaked the denied template repository: %s", s)
	}
}
