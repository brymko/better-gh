package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R36_ProjectItemsArrayContentScrub: the projectsV2 `.../items` LIST returns a JSON ARRAY of items,
// each linking an Issue/PR via an opaque `content` object. A denied repo's linked content must be nulled
// (null-on-denied), not streamed — the array-root sibling of the round-21 object-path content scrub that the
// array-blind ScrubDeniedContent + the suppressed Pass body-scan let leak (round-36 finding-1).
func TestSec_R36_ProjectItemsArrayContentScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "victim/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[`+
			`{"id":1,"content":{"title":"SECRET_ISSUE","body":"creds inside","repository":{"full_name":"victim/secret"}}},`+
			`{"id":2,"content":{"title":"PUBLIC_OK","repository":{"full_name":"acme/pub"}}}`+
			`]`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/orgs/acme/projectsV2/1/items")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "victim/secret") || strings.Contains(s, "creds inside") {
		t.Fatalf("denied repo's linked Issue content leaked via projectsV2 items array: %s", s)
	}
	if !strings.Contains(s, "PUBLIC_OK") {
		t.Fatalf("allowed item wrongly dropped: %s", s)
	}
}
