package specderive

import (
	"encoding/json"
	"testing"
)

// specForResp builds a one-op spec whose GET / response schema is the given JSON, plus a `repo`
// component that is a repository identity (has full_name).
func specForResp(t *testing.T, method, respSchemaJSON string) (*Spec, Op) {
	t.Helper()
	raw := `{"paths":{"/x":{"` + method + `":{"responses":{"200":{"content":{"application/json":{"schema":` +
		respSchemaJSON + `}}}}}}},"components":{"schemas":{"repo":{"properties":{"full_name":{"type":"string"}}}}}}`
	s, err := Load([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range s.Ops() {
		return s, o
	}
	t.Fatal("no op")
	return nil, Op{}
}

func TestRepoReach_Roles(t *testing.T) {
	repoRef := `{"$ref":"#/components/schemas/repo"}`
	cases := []struct {
		name, schema           string
		enum, foreign, subject bool
	}{
		{"subject repo", `{"type":"object","properties":{"repository":` + repoRef + `}}`, false, false, true},
		{"enumerated repos", `{"type":"object","properties":{"items":{"type":"array","items":` + repoRef + `}}}`, true, false, false},
		{"foreign under head", `{"type":"object","properties":{"head":{"type":"object","properties":{"repo":` + repoRef + `}}}}`, false, true, false},
		// the response root being a repo (full_name at $) is the subject; RepoReach skips depth-0 (it is
		// the path repo for path-scoped ops, and runtime passScan/NeedsFilter covers root repos), so only
		// the cross-ref parent is recorded.
		{"foreign parent", `{"type":"object","properties":{"full_name":{"type":"string"},"parent":` + repoRef + `}}`, false, true, false},
		{"minimal repo enum", `{"type":"array","items":{"type":"object","properties":{"id":{},"name":{},"url":{}}}}`, true, false, false},
		{"no repo", `{"type":"object","properties":{"sha":{"type":"string"}}}`, false, false, false},
	}
	for _, c := range cases {
		s, o := specForResp(t, "get", c.schema)
		r := s.RepoReach(o)
		if r.Enum != c.enum || r.Foreign != c.foreign || r.Subject != c.subject {
			t.Errorf("%s: got Enum=%v Foreign=%v Subject=%v, want %v/%v/%v (paths=%v)",
				c.name, r.Enum, r.Foreign, r.Subject, c.enum, c.foreign, c.subject, r.Paths)
		}
	}
}

func TestBuildTable_LocatesNestedAndArrayRepos(t *testing.T) {
	repoRef := `{"$ref":"#/components/schemas/repo"}`
	// an array of objects each nesting a repository → location $[].repository.full_name
	s, _ := specForResp(t, "get", `{"type":"array","items":{"type":"object","properties":{"repository":`+repoRef+`}}}`)
	repoOps, _ := s.BuildTable()
	locs := repoOps["GET /x"]
	if len(locs) != 1 || locs[0] != "$[].repository.full_name" {
		t.Fatalf("BuildTable located %v, want [$[].repository.full_name]", locs)
	}
}

func TestNestsRepoLoc(t *testing.T) {
	for _, c := range []struct {
		loc  []string
		want bool
	}{
		{[]string{"$[].full_name"}, false},
		{[]string{"$[].repository.full_name"}, true},
		{[]string{"$.repository.full_name"}, false},
		{[]string{"$.items[].repository.full_name"}, true},
	} {
		if got := NestsRepoLoc(c.loc); got != c.want {
			t.Errorf("NestsRepoLoc(%v)=%v want %v", c.loc, got, c.want)
		}
	}
}

var _ = json.Marshal
