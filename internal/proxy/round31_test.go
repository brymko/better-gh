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

// TestSec_R31_ViewerPrivateDenied: viewer's owner-private sub-resources (the custodian's secret gists,
// private orgs, projectsV2) must be denied for a loginflow-floored mode=deny token — the GraphQL parallel
// of the round-30 REST /user/* split (round-31).
func TestSec_R31_ViewerPrivateDenied(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny,
		Unscoped: map[string]policy.Access{"user": policy.AccessRead, "meta": policy.AccessRead}}}
	for _, q := range []string{
		`{ viewer { gists(privacy:SECRET,first:1){ nodes{ name files{ text } } } } }`,
		`{ viewer { organizations(first:1){ nodes{ login } } } }`,
		`{ viewer { projectsV2(first:1){ nodes{ title } } } }`,
		`{ viewer { savedReplies(first:1){ nodes{ body } } } }`,
	} {
		var hit bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hit = true
			io.WriteString(w, `{"data":{"viewer":{"x":"SECRET_CUSTODIAN_DATA"}}}`)
		}))
		h := &Handler{
			GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
			Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL, GQLFilter: sch,
		}
		srv := httptest.NewServer(h)
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || hit || strings.Contains(string(b), "SECRET_CUSTODIAN_DATA") {
			t.Errorf("%s: custodian private data not denied (status %d, hit %v): %s", q, resp.StatusCode, hit, b)
		}
		srv.Close()
		upstream.Close()
	}

	// viewer{login} (gh auth identity) must STILL be allowed.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":{"viewer":{"login":"owner"}}}`)
	}))
	defer upstream.Close()
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":"{ viewer { login } }"}`))
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("viewer{login} (gh auth) wrongly denied — the floor must still allow it, status %d", resp.StatusCode)
	}
}
