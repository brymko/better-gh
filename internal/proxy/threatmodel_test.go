package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

const realTokenSentinel = "REAL_GH_TOKEN_e3b0c44298fc"

// Threat model — TOKEN LEAKAGE: the real upstream token must never appear in a client-facing
// response (headers or body), across REST reads/writes, GraphQL, error responses, and the
// GHE handshake shortcuts. The upstream receives it (correctly) but the mock does not echo it.
func TestSec_RealTokenNeverReachesClient(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	var sawUpstreamToken int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), realTokenSentinel) {
			atomic.AddInt32(&sawUpstreamToken, 1) // upstream SHOULD see it
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "graphql") {
			io.WriteString(w, `{"data":{"viewer":{"login":"u"}}}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	st := mustStore(t)
	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessReadWrite}},
	}
	_, secret, err := st.Create("c", pol)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		GithubToken: realTokenSentinel, Store: st, Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: GHEMode, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	type req struct{ method, path, body string }
	reqs := []req{
		{"GET", "/api/v3/repos/o/r/pulls", ""},
		{"POST", "/api/v3/repos/o/r/pulls", `{"title":"x"}`},
		{"POST", "/api/graphql", `{"query":"query{viewer{login}}"}`},
		{"GET", "/api/v3", ""},           // GHE handshake shortcut
		{"GET", "/api/v3/user", ""},      // synthetic identity shortcut
		{"GET", "/api/v3/nope/nope", ""}, // denied → 403
	}
	for _, rq := range reqs {
		var bodyR io.Reader
		if rq.body != "" {
			bodyR = strings.NewReader(rq.body)
		}
		httpReq, _ := http.NewRequest(rq.method, srv.URL+rq.path, bodyR)
		httpReq.Header.Set("Authorization", "token "+secret)
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatalf("%s %s: %v", rq.method, rq.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), realTokenSentinel) {
			t.Errorf("%s %s: real token leaked in response body", rq.method, rq.path)
		}
		for k, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(v, realTokenSentinel) {
					t.Errorf("%s %s: real token leaked in response header %s", rq.method, rq.path, k)
				}
			}
		}
	}
	if atomic.LoadInt32(&sawUpstreamToken) == 0 {
		t.Errorf("sanity: upstream should have received the real token at least once")
	}
}

// Threat model — BYPASS: a denied request must never reach the upstream (no classification
// escape), for both REST and GraphQL.
func TestSec_DeniedRequestNeverReachesUpstream(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)
	st, _ := store.Open(t.TempDir() + "/tokens.json")
	_, secret, err := st.Create("deny", policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		GithubToken: "t", Store: st, Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: GHEMode, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, p := range []struct{ method, path, body string }{
		{"GET", "/api/v3/repos/secret-org/secret/contents/x", ""},
		{"POST", "/api/v3/repos/secret-org/secret/pulls", `{}`},
		{"POST", "/api/graphql", `{"query":"query{repository(owner:\"secret-org\",name:\"secret\"){name}}"}`},
		{"POST", "/api/graphql", `{"query":"query{viewer{login}}"}`}, // user not granted → denied
	} {
		var br io.Reader
		if p.body != "" {
			br = strings.NewReader(p.body)
		}
		rq, _ := http.NewRequest(p.method, srv.URL+p.path, br)
		rq.Header.Set("Authorization", "token "+secret)
		resp, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s expected 403, got %d", p.method, p.path, resp.StatusCode)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("denied requests must not reach upstream, got %d hits", n)
	}
}
