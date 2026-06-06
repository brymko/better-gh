package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R38_EnterpriseBillingCarveOut: a token granted base enterprise read but a `billing="none"`
// per-resource carve-out must NOT read the enterprise's billing financials over GraphQL — the carve-out the
// REST /enterprises/{slug}/billing path enforces must be honored on GraphQL too (round-38: enterprise(slug:)
// degraded every field to base read, bypassing the carve-out). The request must be denied (403), not forwarded.
func TestSec_R38_EnterpriseBillingCarveOut(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{
			Name:        "acme-ent",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"billing": policy.AccessNone},
		}},
	}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"enterprise":{"billingInfo":{"totalAvailableLicenses":9999},"billingEmail":"BILLING_SECRET@x"}}}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)

	resp := postGQL(t, srv.URL, `{ enterprise(slug:"acme-ent"){ billingInfo{ totalAvailableLicenses } billingEmail } }`)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("enterprise billing under billing=none carve-out must be denied, got status %d: %s", resp.StatusCode, b)
	}
	if hit {
		t.Errorf("denied enterprise-billing read reached upstream")
	}

	// base enterprise read of plain metadata (name) must still work (the carve-out is per-resource).
	resp2 := postGQL(t, srv.URL, `{ enterprise(slug:"acme-ent"){ name } }`)
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Errorf("enterprise(slug){name} metadata wrongly denied under a billing-only carve-out, status %d", resp2.StatusCode)
	}
}
