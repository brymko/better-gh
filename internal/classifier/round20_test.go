package classifier

import (
	"strings"
	"testing"
)

func hasScope(scopes []Scope, owner, repo, org, resource string) bool {
	for _, s := range scopes {
		if s.Owner == owner && s.Repo == repo && s.Org == org && s.Resource == resource {
			return true
		}
	}
	return false
}

// Round-20: a GraphQL owner-root reading membersWithRole/teams must emit an org scope tagged with the
// "members"/"teams" per-resource key, so a [org.permissions] carve-out is enforced (REST parity).
func TestR20_GraphQLOrgPerResourceScope(t *testing.T) {
	r := Classify("POST", "/graphql", []byte(`{"query":"{ organization(login:\"acme\"){ membersWithRole(first:10){ nodes{ login } } } }"}`))
	if !hasScope(r.AllScopes(), "", "", "acme", "members") {
		t.Fatalf("membersWithRole must scope to org=acme resource=members, got %+v", r.AllScopes())
	}
	// A pure org-metadata read stays a base ("") scope, not over-restricted.
	r2 := Classify("POST", "/graphql", []byte(`{"query":"{ organization(login:\"acme\"){ name description } }"}`))
	if !hasScope(r2.AllScopes(), "", "", "acme", "") {
		t.Fatalf("organization{name} must stay a base org scope, got %+v", r2.AllScopes())
	}
}

// Round-20: repository{deployKeys} must scope to the "keys" resource (REST parity), so a keys="none"
// carve-out denies the query at the front gate.
func TestR20_GraphQLDeployKeysScope(t *testing.T) {
	r := Classify("POST", "/graphql", []byte(`{"query":"{ repository(owner:\"a\",name:\"b\"){ deployKeys(first:10){ nodes{ key } } } }"}`))
	if !hasScope(r.AllScopes(), "a", "b", "", "keys") {
		t.Fatalf("deployKeys must scope to a/b resource=keys, got %+v", r.AllScopes())
	}
}

// Round-20: a modern prefix_base64 node ID under an ID-typed *oid argument (AddDiscussionCommentInput
// .replyToId) must still be collected — the blind *oid suffix exclusion was a name-based fail-open.
func TestR20_ModernNodeIDUnderOidKeyCollected(t *testing.T) {
	r := Classify("POST", "/graphql", []byte(`{"query":"mutation{ addDiscussionComment(input:{discussionId:\"D_kwDOABCDEF\",replyToId:\"DC_kwDOXYZ123\",body:\"x\"}){ clientMutationId } }"}`))
	got := strings.Join(r.NodeIDs, ",")
	if !strings.Contains(got, "DC_kwDOXYZ123") {
		t.Fatalf("modern node ID under replyToId (*oid key) must be collected, got NodeIDs=%v", r.NodeIDs)
	}
	if !strings.Contains(got, "D_kwDOABCDEF") {
		t.Fatalf("discussionId must be collected, got NodeIDs=%v", r.NodeIDs)
	}
	// A 40-hex git SHA under an *Oid key must NOT be collected (it is a GitObjectID, not a node ID).
	r2 := Classify("POST", "/graphql", []byte(`{"query":"mutation{ createCommitOnBranch(input:{expectedHeadOid:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}){ clientMutationId } }"}`))
	for _, id := range r2.NodeIDs {
		if id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			t.Fatalf("git SHA under expectedHeadOid must not be collected as a node ID")
		}
	}
}
