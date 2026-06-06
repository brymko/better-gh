package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R27_RestOwnerPrivateDenied: the REST owner-private roots (enterprise teams/members, org billing by
// numeric id, legacy team members) must be org-scoped so an [[org]] deny (or default-deny) gates them —
// previously they fell to Defaults.Mode and leaked under mode=allow (round-27).
func TestSec_R27_RestOwnerPrivateDenied(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessNone}},
	}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, `[{"login":"ceo-secret"}]`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, path := range []string{
		"/enterprises/acme/teams/eng/memberships",
		"/enterprises/acme/teams",
		"/teams/acme/members",
	} {
		hit = false
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: owner-private endpoint not denied (status %d): %s", path, resp.StatusCode, b)
		}
		if hit {
			t.Errorf("%s: denied owner-private endpoint reached upstream", path)
		}
	}
}
