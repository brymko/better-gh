package policy

import "testing"

// Round-21: when two org per-resource keys fold to the same resource (a self-contradictory config),
// lookupResource must deterministically pick the MOST RESTRICTIVE access, not a random map-iteration
// winner that could intermittently grant access the operator believed denied.
func TestR21_LookupResourceCollisionMostRestrictive(t *testing.T) {
	perms := map[string]Access{"Members": AccessReadWrite, "MEMBERS": AccessNone}
	for i := 0; i < 200; i++ { // map iteration order is randomized; must be stable across calls
		a, ok := lookupResource(perms, "members")
		if !ok || a != AccessNone {
			t.Fatalf("lookupResource must deterministically return the most restrictive (none), got ok=%v a=%v", ok, a)
		}
	}
	// exact-match fast path still wins.
	if a, ok := lookupResource(map[string]Access{"members": AccessRead}, "members"); !ok || a != AccessRead {
		t.Fatalf("exact match must return read, got ok=%v a=%v", ok, a)
	}
}
