package proxy

// End-to-end tests for npm package-registry proxying: requests for npm.pkg.github.com are routed
// to a SEPARATE upstream under Bearer auth, authorized by the scope owner's `packages` grant, and
// the packument response is scrubbed (tarball-URL rewrite + backing-repo cross-ref redaction).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/policy"
)

const npmPackument = `{` +
	`"name":"@acme/widget","dist-tags":{"latest":"1.0.0"},` +
	`"repository":{"type":"git","url":"git+https://github.com/acme/private-repo.git"},` +
	`"homepage":"https://github.com/acme/private-repo#readme",` +
	`"versions":{"1.0.0":{"name":"@acme/widget","version":"1.0.0",` +
	`"dist":{"tarball":"https://npm.pkg.github.com/download/@acme/widget/1.0.0/abc123","integrity":"sha512-OK"}}}}`

type npmUpstream struct {
	srv      *httptest.Server
	hits     atomic.Int64
	lastPath atomic.Value
	lastAuth atomic.Value
	lastMeth atomic.Value
}

func newNpmUpstream(t *testing.T, status int, body string) *npmUpstream {
	u := &npmUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.lastPath.Store(r.URL.Path)
		u.lastAuth.Store(r.Header.Get("Authorization"))
		u.lastMeth.Store(r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *npmUpstream) str(v atomic.Value) string {
	s, _ := v.Load().(string)
	return s
}

func npmHandler(t *testing.T, pol *policy.Policy, npmUpstreamURL string) *httptest.Server {
	h := &Handler{
		GithubToken: "CUSTODIAN", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, NpmUpstream: npmUpstreamURL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// A packument read is authorized by packages:read on the owner, routed to the npm upstream with
// Bearer auth, and its tarball URL is rewritten to the proxy host. With the backing repo readable,
// the repository cross-ref is preserved.
func TestNpm_PackumentRoutedBearerAndTarballRewritten(t *testing.T) {
	up := newNpmUpstream(t, 200, npmPackument)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{Name: "acme", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"packages": policy.AccessRead}}},
	}
	srv := npmHandler(t, pol, up.srv.URL)

	resp, err := http.Get(srv.URL + "/@acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	if got := up.str(up.lastPath); got != "/@acme/widget" {
		t.Errorf("upstream path = %q, want /@acme/widget", got)
	}
	if got := up.str(up.lastAuth); got != "Bearer CUSTODIAN" {
		t.Errorf("upstream auth = %q, want Bearer CUSTODIAN (custodian token under Bearer)", got)
	}
	s := string(out)
	if strings.Contains(s, "npm.pkg.github.com") {
		t.Errorf("tarball host not rewritten away from the registry: %s", s)
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if !strings.Contains(s, "https://"+host+"/download/@acme/widget/1.0.0/abc123") {
		t.Errorf("tarball not rewritten to the proxy host: %s", s)
	}
	if !strings.Contains(s, "acme/private-repo") {
		t.Errorf("readable backing-repo cross-ref wrongly scrubbed: %s", s)
	}
}

// With packages:read but the backing repo unreadable (base none), the request is allowed but the
// packument's repository/homepage cross-refs are scrubbed — the same repo-level filtering the API
// paths apply.
func TestNpm_PackumentRepoCrossRefScrubbedWhenRepoDenied(t *testing.T) {
	up := newNpmUpstream(t, 200, npmPackument)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{Name: "acme", // base none; packages readable
			Permissions: map[string]policy.Access{"packages": policy.AccessRead}}},
	}
	srv := npmHandler(t, pol, up.srv.URL)

	resp, err := http.Get(srv.URL + "/@acme/widget")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	s := string(out)
	if strings.Contains(s, "private-repo") {
		t.Errorf("denied backing-repo name leaked in packument: %s", s)
	}
	if !strings.Contains(s, "@acme/widget") {
		t.Errorf("authorized package metadata wrongly dropped: %s", s)
	}
}

// A publish (PUT) needs packages:write — packages:read denies it.
func TestNpm_PublishDeniedWithoutWrite(t *testing.T) {
	up := newNpmUpstream(t, 201, `{"ok":true}`)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{Name: "acme",
			Permissions: map[string]policy.Access{"packages": policy.AccessRead}}},
	}
	srv := npmHandler(t, pol, up.srv.URL)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/@acme/widget", strings.NewReader(`{"_id":"@acme/widget"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("publish with packages:read = %d, want 403", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Fatalf("denied publish reached the upstream %d time(s)", up.hits.Load())
	}
}

// A publish with packages:write is forwarded (PUT, Bearer).
func TestNpm_PublishAllowedWithWrite(t *testing.T) {
	up := newNpmUpstream(t, 201, `{"ok":true}`)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{Name: "acme",
			Permissions: map[string]policy.Access{"packages": policy.AccessReadWrite}}},
	}
	srv := npmHandler(t, pol, up.srv.URL)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/@acme/widget", strings.NewReader(`{"_id":"@acme/widget"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("publish with packages:write = %d, want 201", resp.StatusCode)
	}
	if got := up.str(up.lastMeth); got != http.MethodPut {
		t.Errorf("upstream method = %q, want PUT", got)
	}
}

// An owner with no rule under mode=deny is denied.
func TestNpm_UnknownOwnerDeniedUnderDeny(t *testing.T) {
	up := newNpmUpstream(t, 200, npmPackument)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{Name: "acme",
			Permissions: map[string]policy.Access{"packages": policy.AccessRead}}},
	}
	srv := npmHandler(t, pol, up.srv.URL)

	resp, err := http.Get(srv.URL + "/@other/pkg")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown owner = %d, want 403", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Fatalf("denied request reached the upstream")
	}
}

// An npm path that names no package scope (/-/whoami would echo the custodian identity) fails closed.
func TestNpm_NoScopePathFailsClosed(t *testing.T) {
	up := newNpmUpstream(t, 200, `{"username":"custodian"}`)
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}} // even allow-all
	srv := npmHandler(t, pol, up.srv.URL)

	resp, err := http.Get(srv.URL + "/-/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/-/whoami = %d, want 403 (no policy-gatable scope)", resp.StatusCode)
	}
	if up.hits.Load() != 0 {
		t.Fatalf("scope-less npm path reached the upstream (custodian identity could leak)")
	}
}
