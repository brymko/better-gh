package npm

import (
	"encoding/json"
	"strings"
	"testing"

	"better-gh/internal/restfilter"
)

func TestIsRegistryPath(t *testing.T) {
	npmPaths := []string{
		"/@acme/widget",
		"/@acme%2fwidget",
		"/@acme/widget/-/widget-1.0.0.tgz",
		"/download/@acme/widget/1.0.0/abc123",
		"/-/whoami",
		"/-/package/@acme%2fwidget/dist-tags",
	}
	for _, p := range npmPaths {
		if !IsRegistryPath(p) {
			t.Errorf("IsRegistryPath(%q) = false, want true", p)
		}
	}
	apiPaths := []string{
		"/repos/acme/widget", "/orgs/acme/packages", "/user/repos",
		"/graphql", "/users/acme", "/", "/search/code",
	}
	for _, p := range apiPaths {
		if IsRegistryPath(p) {
			t.Errorf("IsRegistryPath(%q) = true, want false (GitHub API path)", p)
		}
	}
}

func TestOwner(t *testing.T) {
	cases := map[string]struct {
		owner string
		ok    bool
	}{
		"/@acme/widget":                       {"acme", true},
		"/@acme%2fwidget":                     {"acme", true},
		"/@acme%2Fwidget":                     {"acme", true},
		"/download/@acme/widget/1.0.0/abc":    {"acme", true},
		"/-/package/@acme%2fwidget/dist-tags": {"acme", true},
		"/@octo-org/pkg/-/pkg-1.2.3.tgz":      {"octo-org", true},
		"/-/whoami":                           {"", false},
		"/-/ping":                             {"", false},
	}
	for path, want := range cases {
		got, ok := Owner(path)
		if got != want.owner || ok != want.ok {
			t.Errorf("Owner(%q) = (%q,%v), want (%q,%v)", path, got, ok, want.owner, want.ok)
		}
	}
}

func TestIsPackument(t *testing.T) {
	yes := []string{"/@acme/widget", "/@acme%2fwidget"}
	for _, p := range yes {
		if !IsPackument(p) {
			t.Errorf("IsPackument(%q) = false, want true", p)
		}
	}
	no := []string{
		"/@acme/widget/-/widget-1.0.0.tgz", // canonical npm tarball
		"/download/@acme/widget/1.0.0/abc", // GitHub tarball
		"/-/whoami",
		"/repos/acme/widget",
	}
	for _, p := range no {
		if IsPackument(p) {
			t.Errorf("IsPackument(%q) = true, want false", p)
		}
	}
}

const packument = `{` +
	`"name":"@acme/widget",` +
	`"dist-tags":{"latest":"1.0.0"},` +
	`"repository":{"type":"git","url":"git+https://github.com/acme/private-repo.git"},` +
	`"homepage":"https://github.com/acme/private-repo#readme",` +
	`"bugs":{"url":"https://github.com/acme/private-repo/issues"},` +
	`"versions":{"1.0.0":{` +
	`"name":"@acme/widget","version":"1.0.0",` +
	`"repository":{"type":"git","url":"git+https://github.com/acme/private-repo.git"},` +
	`"dist":{"tarball":"https://npm.pkg.github.com/download/@acme/widget/1.0.0/abc123","integrity":"sha512-DEADBEEF","shasum":"f00"}}}}`

func TestScrubPackument_RewritesTarballAndKeepsReadableRepo(t *testing.T) {
	out, ok := ScrubPackument([]byte(packument), "proxy.example.com",
		func(string) bool { return true }, restfilter.RepoFromWebURL)
	if !ok {
		t.Fatal("ScrubPackument failed on valid body")
	}
	s := string(out)
	if strings.Contains(s, "npm.pkg.github.com") {
		t.Errorf("registry host not rewritten: %s", s)
	}
	if !strings.Contains(s, "https://proxy.example.com/download/@acme/widget/1.0.0/abc123") {
		t.Errorf("tarball not rewritten to proxy host: %s", s)
	}
	// readable repo → cross-refs preserved
	if !strings.Contains(s, "acme/private-repo") {
		t.Errorf("readable repo cross-ref wrongly scrubbed: %s", s)
	}
	if !strings.Contains(s, "sha512-DEADBEEF") {
		t.Errorf("dist.integrity not preserved: %s", s)
	}
}

func TestScrubPackument_NullsCrossRefWhenRepoDenied(t *testing.T) {
	out, ok := ScrubPackument([]byte(packument), "proxy.example.com",
		func(repo string) bool { return repo != "acme/private-repo" }, restfilter.RepoFromWebURL)
	if !ok {
		t.Fatal("ScrubPackument failed on valid body")
	}
	s := string(out)
	if strings.Contains(s, "private-repo") {
		t.Errorf("denied repo cross-ref leaked: %s", s)
	}
	// the package itself is still served
	if !strings.Contains(s, "@acme/widget") {
		t.Errorf("package metadata wrongly dropped: %s", s)
	}
	// tarball still rewritten (so the download is policy-checked)
	if !strings.Contains(s, "https://proxy.example.com/download/@acme/widget/1.0.0/abc123") {
		t.Errorf("tarball not rewritten: %s", s)
	}
	// structurally valid JSON with repository nulled
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("scrubbed body not valid JSON: %v", err)
	}
	if doc["repository"] != nil {
		t.Errorf("repository not nulled: %v", doc["repository"])
	}
	if doc["homepage"] != "" {
		t.Errorf("homepage not blanked: %v", doc["homepage"])
	}
}

func TestScrubPackument_FailsClosedOnUnparseable(t *testing.T) {
	if _, ok := ScrubPackument([]byte("<html>not json</html>"), "h",
		func(string) bool { return true }, restfilter.RepoFromWebURL); ok {
		t.Fatal("ScrubPackument must fail closed on a non-JSON body")
	}
}

func TestScrubPackument_LeavesNonGitHubRepo(t *testing.T) {
	body := `{"name":"@acme/x","repository":{"type":"git","url":"https://gitlab.com/acme/x.git"}}`
	out, ok := ScrubPackument([]byte(body), "h", func(string) bool { return false }, restfilter.RepoFromWebURL)
	if !ok {
		t.Fatal("unexpected failure")
	}
	if !strings.Contains(string(out), "gitlab.com/acme/x") {
		t.Errorf("non-GitHub repo wrongly scrubbed (policy does not govern it): %s", out)
	}
}
