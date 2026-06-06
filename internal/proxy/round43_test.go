package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// TestR43_ErrorsScrubTrailingPunctuation pins round-43 F6: the GraphQL errors[] repo-name scrub must catch a
// denied repo named with trailing sentence punctuation (GitHub permission messages end in '.') and a
// single-char repo segment — the prior regex captured the trailing '.' (so the dotted token missed the
// carve-out's exact name) and required a 2+ char repo.
func TestR43_ErrorsScrubTrailingPunctuation(t *testing.T) {
	denied := func(ownerRepo string) bool { return strings.EqualFold(ownerRepo, "secretcorp/private-upstream") }
	msg := "You do not have permission to view pull requests in secretcorp/private-upstream."
	got, _ := scrubDeniedRepoStrings(msg, denied).(string)
	if strings.Contains(got, "private-upstream") {
		t.Fatalf("F6: trailing-'.' denied repo name not scrubbed: %q", got)
	}

	deniedX := func(ownerRepo string) bool { return strings.EqualFold(ownerRepo, "secretcorp/x") }
	gotX, _ := scrubDeniedRepoStrings("access blocked in secretcorp/x.", deniedX).(string)
	if strings.Contains(gotX, "secretcorp/x") {
		t.Fatalf("F6: single-char denied repo not scrubbed: %q", gotX)
	}

	// an allowed repo name must NOT be scrubbed (no over-redaction).
	allow := func(string) bool { return false }
	keep, _ := scrubDeniedRepoStrings("see octocat/hello-world for details.", allow).(string)
	if !strings.Contains(keep, "octocat/hello-world") {
		t.Fatalf("F6: allowed repo name wrongly scrubbed: %q", keep)
	}
}

// TestR43_AcceptedPermissionsHeaderStripped pins round-43 F7: X-Accepted-GitHub-Permissions (which discloses
// the custodian token's class + the endpoint's required permissions) is stripped from forwarded responses.
func TestR43_AcceptedPermissionsHeaderStripped(t *testing.T) {
	src := http.Header{}
	src.Set("X-Accepted-Github-Permissions", "issues=write")
	src.Set("Content-Type", "application/json")
	dst := http.Header{}
	copyResponseHeaders(dst, src, false)
	if dst.Get("X-Accepted-Github-Permissions") != "" {
		t.Fatal("F7: X-Accepted-GitHub-Permissions not stripped")
	}
	if dst.Get("Content-Type") == "" {
		t.Fatal("F7: Content-Type wrongly stripped")
	}
}
