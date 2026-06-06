package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R45_CopilotSpaceWriteOpaqueFailClosed pins round-45 F1 (instance A): a WRITE to a non-path-scoped
// Pass op whose response names repos only by an opaque numeric id (copilot-spaces) must fail closed on the
// write path too — the GET twin already does via opaqueRepoIDOps, but the write path skipped it.
func TestSec_R45_CopilotSpaceWriteOpaqueFailClosed(t *testing.T) {
	pol := &policy.Policy{
		Org:  []policy.OrgRule{{Name: "acme", Access: policy.AccessReadWrite}},
		Repo: []policy.RepoRule{{Name: "acme/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"number":42,"resources_attributes":[{"type":"repository","metadata":{"repository_id":999,"name":"secret","file_path":"/internal/keys.txt"}}]}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/orgs/acme/copilot-spaces/42", strings.NewReader(`{"description":"x"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F1: copilot-space write should fail closed (403), got %d: %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), "keys.txt") || strings.Contains(string(b), "999") {
		t.Fatalf("F1: copilot-space write leaked opaque repo metadata: %s", b)
	}
}

// TestSec_R45_StorageRecordWriteBareRepoScanned pins round-45 F1 (instance B): a write whose response carries
// a bare org-qualified `repository` string (storage-record) is body-scanned on the write path, so a denied
// repo's name/existence fails closed instead of streaming.
func TestSec_R45_StorageRecordWriteBareRepoScanned(t *testing.T) {
	pol := &policy.Policy{
		Org:  []policy.OrgRule{{Name: "acme", Access: policy.AccessReadWrite}},
		Repo: []policy.RepoRule{{Name: "acme/secret", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"storage_records":[{"repository":"secret","digest":"sha256:abc"}]}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/orgs/acme/artifacts/metadata/storage-record", strings.NewReader(`{"digest":"sha256:abc"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), `"secret"`) && resp.StatusCode == http.StatusOK {
		t.Fatalf("F1: storage-record write leaked the denied repo name (status %d): %s", resp.StatusCode, b)
	}
}

// TestSec_R45_SelectedRepoIDsWriteFailClosed pins round-45 F5: a write naming target repos by numeric
// selected_repository_ids[] is failed closed when a per-repo carve-out under the org is in effect.
func TestSec_R45_SelectedRepoIDsWriteFailClosed(t *testing.T) {
	pol := &policy.Policy{
		Org:  []policy.OrgRule{{Name: "acme", Access: policy.AccessReadWrite}},
		Repo: []policy.RepoRule{{Name: "acme/secret", Permissions: map[string]policy.Access{"actions": policy.AccessNone}}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/orgs/acme/actions/secrets/CI/repositories", strings.NewReader(`{"selected_repository_ids":[999]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("F5: selected_repository_ids[] write under an actions carve-out should fail closed (403), got %d", resp.StatusCode)
	}
}
