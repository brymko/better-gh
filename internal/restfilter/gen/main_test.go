package main

import (
	"encoding/json"
	"testing"
)

func obj(s string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		panic(err)
	}
	return m
}

// nestsRepoLoc must match the runtime restfilter.nestsRepoInElement classification.
func TestGen_NestsRepoLoc(t *testing.T) {
	cases := []struct {
		locs []string
		want bool
	}{
		{[]string{"$[].full_name"}, false},                         // element IS the repo
		{[]string{"$[].repository.full_name"}, true},               // element nests a repo
		{[]string{"$.items[].repository.full_name"}, true},         // search
		{[]string{"$[].payload.issue.repository.full_name"}, true}, // events
		{[]string{"$[].repo.name"}, true},                          // events minimal repo
		{[]string{"$.repository.full_name"}, false},                // singleton (no array)
		{[]string{"$[].full_name", "$[].repo.full_name"}, true},    // star+json: one nests
	}
	for _, c := range cases {
		if got := nestsRepoLoc(c.locs); got != c.want {
			t.Errorf("nestsRepoLoc(%v) = %v, want %v", c.locs, got, c.want)
		}
	}
}

// findCrossRef must detect a foreign repo embedded under a cross-ref field (head/base/parent/source/…)
// and ignore an own-repo `repository` field (which find() locates as a normal drop, not a scrub).
func TestGen_FindCrossRef(t *testing.T) {
	g := &generator{
		schemas:  map[string]map[string]any{},
		repoComp: map[string]bool{"#/components/schemas/repo": true},
	}
	repoRef := `{"$ref":"#/components/schemas/repo"}`

	// A pull-request shape: head.repo + base.repo are cross-ref repos → must be detected.
	pr := obj(`{"type":"object","properties":{
		"title":{"type":"string"},
		"head":{"type":"object","properties":{"repo":` + repoRef + `}},
		"base":{"type":"object","properties":{"repo":` + repoRef + `}}}}`)
	if !g.findCrossRef(pr, "$", map[string]bool{}, 0) {
		t.Errorf("pull-request head/base.repo cross-ref not detected")
	}

	// A repo object with parent/source (a fork) → cross-ref.
	fork := obj(`{"type":"object","properties":{"full_name":{"type":"string"},"parent":` + repoRef + `,"source":` + repoRef + `}}`)
	if !g.findCrossRef(fork, "$", map[string]bool{}, 0) {
		t.Errorf("fork parent/source cross-ref not detected")
	}

	// An issue with only its OWN repository (no cross-ref field) → NOT a write-scrub candidate.
	issue := obj(`{"type":"object","properties":{"title":{"type":"string"},"repository":` + repoRef + `}}`)
	if g.findCrossRef(issue, "$", map[string]bool{}, 0) {
		t.Errorf("own-repo `repository` must not be flagged as a cross-ref")
	}

	// A plain object with no repo at all.
	plain := obj(`{"type":"object","properties":{"sha":{"type":"string"},"merged":{"type":"boolean"}}}`)
	if g.findCrossRef(plain, "$", map[string]bool{}, 0) {
		t.Errorf("no-repo response must not be flagged")
	}
}
