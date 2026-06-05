package policy

import (
	"strings"
	"testing"
)

// TestR19_ValidateResourceKeys pins round-19 D2: a misspelled repo per-resource key must be
// rejected, not silently accepted (which would degrade the intended per-resource `none` to base
// access). Known keys and open-ended ORG keys are accepted.
func TestR19_ValidateResourceKeys(t *testing.T) {
	// A typo'd repo key is rejected.
	bad := &Policy{Repo: []RepoRule{{Name: "o/r", Access: AccessNone, Permissions: map[string]Access{"contnets": AccessNone}}}}
	err := bad.ValidateResourceKeys()
	if err == nil {
		t.Fatal("ValidateResourceKeys accepted a misspelled repo per-resource key 'contnets'")
	}
	if !strings.Contains(err.Error(), "contnets") {
		t.Errorf("error should name the bad key, got: %v", err)
	}

	// Every canonical repo key is accepted.
	for _, k := range []string{"pulls", "issues", "contents", "actions", "releases", "commits", "branches", "checks", "comments", "hooks", "deployments", "pages", "keys", "metadata"} {
		p := &Policy{Repo: []RepoRule{{Name: "o/r", Access: AccessNone, Permissions: map[string]Access{k: AccessRead}}}}
		if err := p.ValidateResourceKeys(); err != nil {
			t.Errorf("canonical repo key %q rejected: %v", k, err)
		}
	}

	// Org per-resource keys are open-ended (any org subpath segment) and must NOT be validated.
	org := &Policy{Org: []OrgRule{{Name: "acme", Access: AccessRead, Permissions: map[string]Access{"members": AccessNone, "anything-goes": AccessNone}}}}
	if err := org.ValidateResourceKeys(); err != nil {
		t.Errorf("org per-resource keys must not be validated (open-ended), got: %v", err)
	}
}
