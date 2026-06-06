package gqlfilter

import (
	"strings"
	"testing"
)

// TestR35_NavigatedUserPrivateMarked pins that the augmenter marks a navigated User (and injects per-field
// markers) when an owner-private field (email/gists/savedReplies/...) is selected via an author/owner edge,
// but does NOT mark a plain author{login} (which is reached everywhere — coarse-marking it would break it).
func TestR35_NavigatedUserPrivateMarked(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ repository(owner:"a",name:"r"){ pullRequests(first:1){ nodes{ author{ ... on User {
		email savedReplies(first:1){nodes{body}} gists(first:1,privacy:SECRET){nodes{name}} } } } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, userMarkerAlias) {
		t.Fatalf("navigated User with private fields not marked:\n%s", out)
	}
	for _, want := range []string{ownerMemberMarkerPrefix + "email", ownerMemberMarkerPrefix + "savedReplies", ownerMemberMarkerPrefix + "gists"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing per-field marker %q:\n%s", want, out)
		}
	}
	out2, err := s.Augment(`{ repository(owner:"a",name:"r"){ issue(number:1){ author{ login } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, userMarkerAlias) {
		t.Fatalf("plain author{login} wrongly user-marked — would over-redact every author:\n%s", out2)
	}
}

// TestR35_NavigatedUserPrivateRedactedByCategory pins the round-35 finding-2 fix: a navigated User's
// owner-private fields are nulled when the user_private/gists CATEGORY is denied — even when the user's
// LOGIN is org-ALLOWED (the documented `[[org]] name="<login>"` repo-enumeration grant). The org-login gate
// alone (round-28) would have left them streaming; the category gate closes it. And when the category is
// granted, the fields are kept.
func TestR35_NavigatedUserPrivateRedactedByCategory(t *testing.T) {
	// ownerAllowed: the user's login is org-ALLOWED (denied=false for any owner) — the [[org]] grant case.
	ownerAllowed := func(string, string) bool { return false }
	// categoryDenied: user_private AND gists are denied (default-deny token with a repo grant).
	categoryDenied := func(string) bool { return true }

	body := func() map[string]any {
		return map[string]any{"author": map[string]any{
			userMarkerAlias:                          "octocat",
			ownerMemberMarkerPrefix + "email":        "User",
			ownerMemberMarkerPrefix + "gists":        "User",
			ownerMemberMarkerPrefix + "savedReplies": "User",
			"email":                                  "secret@custodian.example",
			"gists":                                  map[string]any{"nodes": []any{map[string]any{"name": "AWS_KEYS", "files": []any{map[string]any{"text": "AWS_SECRET=AKIA..."}}}}},
			"savedReplies":                           map[string]any{"nodes": []any{map[string]any{"body": "PRIVATE_REPLY"}}},
			"login":                                  "octocat",
		}}
	}

	red := RedactDeniedOwnerPrivate(body(), ownerAllowed, categoryDenied).(map[string]any)
	js := mustJSON(red)
	for _, leak := range []string{"secret@custodian.example", "AWS_SECRET=AKIA", "PRIVATE_REPLY"} {
		if strings.Contains(js, leak) {
			t.Fatalf("navigated User's private data leaked under category-denied (org-login allowed): %q in %s", leak, js)
		}
	}
	if !strings.Contains(js, "octocat") || strings.Contains(js, "bghOwner") || strings.Contains(js, "bghOrgMem") {
		t.Fatalf("public login wrongly redacted or marker leaked: %s", js)
	}

	// category GRANTED → kept (operator explicitly granted user_private/gists).
	categoryAllowed := func(string) bool { return false }
	keep := RedactDeniedOwnerPrivate(body(), ownerAllowed, categoryAllowed).(map[string]any)
	jk := mustJSON(keep)
	for _, want := range []string{"secret@custodian.example", "AWS_SECRET=AKIA", "PRIVATE_REPLY"} {
		if !strings.Contains(jk, want) {
			t.Fatalf("user-private field wrongly redacted when category granted: %q missing from %s", want, jk)
		}
	}
}

// TestR35_GistFieldGatedOnGistsCategory pins that a navigated User's gist fields are gated on the GISTS
// category specifically: with user_private granted but gists denied, gists are nulled; email is kept.
func TestR35_GistFieldGatedOnGistsCategory(t *testing.T) {
	ownerAllowed := func(string, string) bool { return false }
	// only gists denied; user_private allowed.
	gistsDenied := func(field string) bool { return UserGistField(field) }
	red := RedactDeniedOwnerPrivate(map[string]any{"author": map[string]any{
		userMarkerAlias:                   "octocat",
		ownerMemberMarkerPrefix + "gists": "User",
		ownerMemberMarkerPrefix + "email": "User",
		"gists":                           map[string]any{"nodes": []any{map[string]any{"name": "SECRET_GIST"}}},
		"email":                           "pub@example.com",
		"login":                           "octocat",
	}}, ownerAllowed, gistsDenied).(map[string]any)
	js := mustJSON(red)
	if strings.Contains(js, "SECRET_GIST") {
		t.Fatalf("gist field not nulled under gists-denied: %s", js)
	}
	if !strings.Contains(js, "pub@example.com") {
		t.Fatalf("email wrongly nulled when only gists denied (user_private granted): %s", js)
	}
}
