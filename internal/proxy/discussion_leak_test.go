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

// Regression for FINDING I (HIGH) e2e: a viewer-scoped read of repositoryDiscussionComments
// reaches DiscussionComment with no tagged ancestor. With the indirect-membership path now
// derived, the augmented query carries discussion{repository{nameWithOwner}}, GitHub returns
// the marker, and the filter redacts comments from denied repos. Policy here allows only the
// "user" category; every repo is denied by default.
func TestSec_E2E_DiscussionCommentRedacted(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// GitHub answers the augmented query: the injected marker reveals each comment's repo.
		io.WriteString(w, `{"data":{"viewer":{"repositoryDiscussionComments":{"nodes":[`+
			`{"body":"DENIED_SECRET","bghRepoTagZ9":{"repository":{"nameWithOwner":"blocked-org/secret"}}},`+
			`{"body":"ALLOWED_OK","bghRepoTagZ9":{"repository":{"nameWithOwner":"allowed-org/pub"}}}]}}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "allowed-org/pub", Access: policy.AccessRead}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := `{"query":"query { viewer { repositoryDiscussionComments(first:50){ nodes { body } } } }"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)
	if strings.Contains(s, "DENIED_SECRET") {
		t.Fatalf("denied-repo discussion comment leaked: %s", s)
	}
	if !strings.Contains(s, "ALLOWED_OK") {
		t.Fatalf("allowed-repo discussion comment was wrongly dropped: %s", s)
	}
	if strings.Contains(s, "bghRepoTagZ9") {
		t.Fatalf("marker leaked to client: %s", s)
	}
}
