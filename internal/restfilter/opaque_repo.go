package restfilter

// opaqueRepoIDOps are Pass GET ops whose response identifies its repository ONLY by an opaque
// NUMERIC id (no full_name, no repository_url, not the {id,name,url} minimal-repo shape), so neither
// the OpenAPI generator (which locates full_name/minimal-repo) nor the ContainsDeniedRepo body-scan
// (full_name/repository_url/minimal-repo) can map it to owner/repo. The proxy must fail these CLOSED
// when they are NOT path-scoped (round-20): the Copilot coding-agent task lookups /agents/tasks and
// /agents/tasks/{task_id} name their target repo by a numeric repository_id, so under default=allow
// the empty-scope read rides the Pass body-scan (which cannot see a numeric id) and leaks a denied
// repo's task data. The path-scoped sibling /agents/repos/{owner}/{repo}/tasks[/{id}] is scoped to a
// single repository by the classifier (round-19 F6) and never reaches this branch.
//
// Maintenance: hand-maintained, but TestSpecCoverage_OpaqueRepoIDOps DERIVES the detectable members
// from the embedded spec (every Pass GET op whose response declares a `repository_id` property the
// generator/body-scan can't map) and fails the build if one is missing — so the round-20/33/35 class
// (a denied repo named only by a numeric id) cannot silently grow. When refreshing, run the suite and
// add any op the guard flags; also audit ops whose repo id hides under an opaque `additionalProperties`
// metadata object (which the guard cannot see) and add those by hand.
var opaqueRepoIDOps = []string{
	"/agents/tasks",
	"/agents/tasks/{task_id}",
	// Copilot Spaces: a space's resources_attributes[].metadata names an attached repo only by a numeric
	// repository_id (+ bare name / file_path), and the /resources[/{id}] metadata is an opaque
	// additionalProperties object — neither the generator nor the body-scan can map it, so a token carved
	// out of a private repo otherwise learned its existence + id + name + internal file paths (round-35).
	// Fail closed (the numeric id carries no in-body owner to redact against) — the /agents/tasks precedent.
	"/orgs/{org}/copilot-spaces",
	"/orgs/{org}/copilot-spaces/{space_number}",
	"/orgs/{org}/copilot-spaces/{space_number}/resources",
	"/orgs/{org}/copilot-spaces/{space_number}/resources/{space_resource_id}",
	"/users/{username}/copilot-spaces",
	"/users/{username}/copilot-spaces/{space_number}",
	"/users/{username}/copilot-spaces/{space_number}/resources",
	"/users/{username}/copilot-spaces/{space_number}/resources/{space_resource_id}",
	// Webhook deliveries name the event's repo by a bare numeric repository_id (no repository_name), and
	// attestation-by-digest bundles carry the producing repo's numeric repository_id — both unmappable in
	// body, so a token carved out of a private repo would learn its id/existence. Surfaced by the derived
	// TestSpecCoverage_OpaqueRepoIDOps guard (the rest of the round-20/33 class). Fail closed when not
	// path-scoped. (/app/hook/* additionally needs a GitHub App JWT the user-token custodian lacks, so
	// failing it closed costs nothing.)
	"/app/hook/deliveries",
	"/app/hook/deliveries/{delivery_id}",
	"/orgs/{org}/hooks/{hook_id}/deliveries",
	"/orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}",
	"/orgs/{org}/attestations/{subject_digest}",
	"/users/{username}/attestations/{subject_digest}",
	// Org rulesets target repos by OPAQUE NUMERIC id in two combinator-buried shapes the body-scan cannot
	// map: conditions.repository_id.repository_ids[] (a name-less id array) and a required-workflow rule's
	// parameters.workflows[].repository_id (a name-less id) — see the rules[] 22-member oneOf. A token
	// granted org rulesets=read with a per-repo `none` carve-out otherwise learns the denied repo's id +
	// existence. Fail closed when not path-scoped (the numeric id carries no in-body owner to redact, and
	// nulling every id would equally degrade the response); the repo-scoped /repos/{o}/{r}/rulesets sibling
	// is gated by its path scope and never reaches here. Surfaced by the round-42-extended
	// TestSpecCoverage_OpaqueRepoIDOps (now traversing oneOf/anyOf/allOf + the plural repository_ids array).
	"/orgs/{org}/rulesets",
	"/orgs/{org}/rulesets/{ruleset_id}",
}

var opaqueRepoIDTemplates []opTemplate

func init() {
	for _, p := range opaqueRepoIDOps {
		opaqueRepoIDTemplates = append(opaqueRepoIDTemplates, parseTemplate(p, nil))
	}
}

// HasOpaqueRepoID reports whether normPath is a Pass GET op whose response names its repository only
// by an opaque numeric id the response filter cannot map — so it must fail closed when not
// path-scoped, rather than ride the numeric-id-blind ContainsDeniedRepo body scan.
func HasOpaqueRepoID(normPath string) bool {
	ps := segments(normPath)
	for _, t := range opaqueRepoIDTemplates {
		if t.matches(ps) {
			return true
		}
	}
	return false
}
