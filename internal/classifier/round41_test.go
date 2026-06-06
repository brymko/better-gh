package classifier

import (
	"strings"
	"testing"
)

// TestR41_SplitTargetViaVariable pins the round-41 finding-3 fix: createSponsorsTier's split
// repositoryOwnerLogin+repositoryName target is scoped even when the WHOLE input is a GraphQL variable
// (the ObjectValue split detector never saw it; walkVarsForIDs now does).
func TestR41_SplitTargetViaVariable(t *testing.T) {
	body := `{"query":"mutation($i:CreateSponsorsTierInput!){ createSponsorsTier(input:$i){ clientMutationId } }",` +
		`"variables":{"i":{"amount":5,"description":"d","repositoryName":"secret","repositoryOwnerLogin":"victimorg","sponsorableLogin":"victimorg"}}}`
	r := Classify("POST", "/graphql", []byte(body))
	if !r40ScopesRepo(r, "victimorg", "secret") {
		t.Errorf("split repo target supplied as a variable not scoped: %+v", r.AllScopes())
	}
}

// TestR41_MutationWalkBudget pins the round-41 finding-7 DoS bound: a pathological many-op/shared-fragment
// mutation document is handled (not an O(ops×fields) hang) — the node-ID/scope walk now shares a visit budget.
func TestR41_MutationWalkBudget(t *testing.T) {
	var fields strings.Builder
	for i := 0; i < 4000; i++ {
		fields.WriteString("f")
		fields.WriteString(string(rune('a' + i%26)))
		fields.WriteByte(' ')
	}
	var q strings.Builder
	q.WriteString("fragment F on Mutation{ ")
	q.WriteString(fields.String())
	q.WriteString(" }\n")
	for i := 0; i < 2000; i++ {
		q.WriteString("mutation{ ...F }\n")
	}
	// must return promptly without hanging; the result is irrelevant (budget-exhausted → fail closed).
	_ = Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q.String())+`}`))
}
