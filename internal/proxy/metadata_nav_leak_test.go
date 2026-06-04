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

// Regression for audit F1 (HIGH): cross-repo navigation must not leak a base=none repo's
// metadata-class CONTENT (Discussion/Milestone/Project/Tag…) just because the repo carries a
// non-none per-resource grant. Those content types map to resource "metadata" (no dedicated
// key); before the fix the filter authorized every "metadata" object with the lenient
// CanReadAnything, which is true whenever ANY per-resource permission is non-none — so a
// navigated Discussion in a base=none + issues=read repo was forwarded. The fix keeps only the
// repository CONTAINER leniently and routes content objects through the strict Evaluate, exactly
// as the direct path repository(secret){discussions{body}} already is.
func TestSec_E2E_MetadataContentNavRedacted_F1(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	// Upstream answers the augmented navigation query: each object self-identifies its repo via
	// the injected markers. The secret repo's container, one Discussion (metadata-class content),
	// and one Issue (per-resource "issues" content) all carry acme/secret markers.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{`+
			`"name":"public","bghRepoTagZ9":"acme/public","bghRepoTypeZ9":"Repository",`+
			`"owner":{"repositories":{"nodes":[`+
			`{"name":"secret","bghRepoTagZ9":"acme/secret","bghRepoTypeZ9":"Repository",`+
			`"discussions":{"nodes":[{"title":"DT","body":"SECRET_DISCUSSION_BODY",`+
			`"bghRepoTagZ9":{"repository":{"nameWithOwner":"acme/secret"}},"bghRepoTypeZ9":"Discussion"}]},`+
			`"issues":{"nodes":[{"title":"IT","body":"ALLOWED_ISSUE_BODY",`+
			`"bghRepoTagZ9":{"repository":{"nameWithOwner":"acme/secret"}},"bghRepoTypeZ9":"Issue"}]}`+
			`}]}}}}}`)
	}))
	t.Cleanup(upstream.Close)

	// Operator intent: "only read acme/secret's issues" — base none + issues=read. acme/public
	// is the (allowed) navigation entry point.
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{
			{Name: "acme/public", Access: policy.AccessRead},
			{Name: "acme/secret", Access: policy.AccessNone, Permissions: map[string]policy.Access{"issues": policy.AccessRead}},
		},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := `{"query":"query { repository(owner:\"acme\",name:\"public\") { name owner { repositories(first:50){ nodes { name discussions(first:50){ nodes { title body } } issues(first:50){ nodes { title body } } } } } } }"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (request is allowed; the denied content is redacted in-body), got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "SECRET_DISCUSSION_BODY") {
		t.Fatalf("F1 leak: base=none repo's discussion content forwarded via navigation: %s", s)
	}
	if !strings.Contains(s, "ALLOWED_ISSUE_BODY") {
		t.Fatalf("issues=read content was wrongly redacted (over-redaction): %s", s)
	}
	// The granted child (the issue) must survive — proving the container was kept STRUCTURALLY,
	// not nulled wholesale — while the navigated base=none container's OWN metadata scalar
	// (its name) is stripped, since the direct repository(secret){name} is denied (audit F3).
	if !strings.Contains(s, `"title":"IT"`) {
		t.Fatalf("repository container was wrongly redacted, losing its granted children: %s", s)
	}
	if strings.Contains(s, `"name":"secret"`) {
		t.Fatalf("F3 leak: navigated base=none container's metadata scalar (name) forwarded: %s", s)
	}
	if !strings.Contains(s, `"name":"public"`) {
		t.Fatalf("entry container's metadata (base=read) was wrongly stripped: %s", s)
	}
	if strings.Contains(s, "bghRepoTagZ9") || strings.Contains(s, "bghRepoTypeZ9") {
		t.Fatalf("marker leaked to client: %s", s)
	}
}
