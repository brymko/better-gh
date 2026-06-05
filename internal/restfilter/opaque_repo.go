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
// Maintenance: hand-maintained. When refreshing against a new spec, audit Pass ops whose response
// schema carries a bare numeric repository_id with no full_name/repository_url and add them here.
var opaqueRepoIDOps = []string{
	"/agents/tasks",
	"/agents/tasks/{task_id}",
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
