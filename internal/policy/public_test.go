package policy

import (
	"encoding/json"
	"testing"

	"better-gh/internal/classifier"
)

// The public baseline must round-trip through both operator-facing paths: the TOML spec
// (policy.toml / console "paste spec") and the JSON the console builder POSTs.
func TestPublic_RoundTrips(t *testing.T) {
	p, err := ParseTOML([]byte("[defaults]\nmode = \"deny\"\npublic = \"read\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.Public != AccessRead {
		t.Fatalf("TOML public=read parsed as %v, want AccessRead", p.Defaults.Public)
	}

	var fromJSON Policy
	if err := json.Unmarshal([]byte(`{"defaults":{"mode":"deny","public":"read"}}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Defaults.Public != AccessRead {
		t.Fatalf("JSON public=read parsed as %v, want AccessRead", fromJSON.Defaults.Public)
	}

	// Default (omitted) must be none, and must serialize back without a stray public key.
	none, _ := ParseTOML([]byte("[defaults]\nmode = \"deny\"\n"))
	if none.Defaults.Public != AccessNone {
		t.Fatalf("omitted public parsed as %v, want AccessNone", none.Defaults.Public)
	}
	b, _ := json.Marshal(none)
	if string(b) == "" || containsKey(b, "public") {
		t.Fatalf("public=none should be omitted from JSON, got %s", b)
	}
}

func containsKey(b []byte, key string) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	d, _ := m["defaults"].(map[string]any)
	_, ok := d["public"]
	return ok
}

func TestPublicReadEligible(t *testing.T) {
	base := func(public Access, repos []RepoRule, orgs []OrgRule) *Policy {
		return &Policy{Defaults: Defaults{Mode: ModeDeny, Public: public}, Repo: repos, Org: orgs}
	}

	cases := []struct {
		name   string
		pol    *Policy
		repo   string
		org    string
		access classifier.AccessLevel
		want   bool
	}{
		{"public=none never eligible", base(AccessNone, nil, nil), "o/r", "o", classifier.Read, false},
		{"public=read, no rule, read", base(AccessRead, nil, nil), "o/r", "o", classifier.Read, true},
		{"public=read never grants write", base(AccessRead, nil, nil), "o/r", "o", classifier.Write, false},
		{"explicit repo allow rule governs (baseline excluded)", base(AccessRead, []RepoRule{{Name: "o/r", Access: AccessRead}}, nil), "o/r", "o", classifier.Read, false},
		{"explicit repo deny rule governs (baseline must not override)", base(AccessRead, []RepoRule{{Name: "o/r", Access: AccessNone}}, nil), "o/r", "o", classifier.Read, false},
		{"explicit org rule governs", base(AccessRead, nil, []OrgRule{{Name: "o", Access: AccessRead}}), "o/r", "o", classifier.Read, false},
		{"case-insensitive rule match still governs", base(AccessRead, []RepoRule{{Name: "O/R", Access: AccessNone}}, nil), "o/r", "o", classifier.Read, false},
		{"other repo under same owner still eligible", base(AccessRead, []RepoRule{{Name: "o/secret", Access: AccessNone}}, nil), "o/other", "o", classifier.Read, true},
	}
	for _, c := range cases {
		if got := c.pol.PublicReadEligible(c.repo, c.org, c.access); got != c.want {
			t.Errorf("%s: PublicReadEligible(%q,%q,%v) = %v, want %v", c.name, c.repo, c.org, c.access, got, c.want)
		}
	}
}
