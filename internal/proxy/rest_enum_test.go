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

// Regression for FINDING K (HIGH): the GraphQL filter redacts denied repos from enumeration,
// but the equivalent REST endpoints were unfiltered, so a client with the user/search
// categories could enumerate denied repos' metadata (/user/repos) and read their code
// (/search/code). REST enumeration/search responses are now filtered too.
func TestSec_E2E_RestEnumerationFiltered(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/user/repos":
			io.WriteString(w, `[{"full_name":"allowed-org/pub"},{"full_name":"blocked-org/secret","description":"REST_SECRET_META"}]`)
		case strings.HasPrefix(r.URL.Path, "/search/code"):
			io.WriteString(w, `{"total_count":1,"items":[{"name":"x","repository":{"full_name":"blocked-org/secret"},"text_matches":"REST_CODE_LEAK"}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessRead, "search": policy.AccessRead}},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/pub", Access: policy.AccessRead},
			{Name: "blocked-org/secret", Access: policy.AccessNone},
		},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// /user/repos must not list the denied repo.
	st, body := getBody(t, srv.URL+"/user/repos")
	if st != 200 {
		t.Fatalf("/user/repos status=%d", st)
	}
	if strings.Contains(body, "REST_SECRET_META") || strings.Contains(body, "blocked-org/secret") {
		t.Errorf("/user/repos leaked denied repo: %s", body)
	}
	if !strings.Contains(body, "allowed-org/pub") {
		t.Errorf("/user/repos dropped allowed repo: %s", body)
	}

	// /search/code must not return the denied repo's code.
	if _, body := getBody(t, srv.URL+"/search/code?q=x"); strings.Contains(body, "REST_CODE_LEAK") {
		t.Errorf("/search/code leaked denied repo code: %s", body)
	}
}

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}
