package restfilter

// Cross-repo CONTENT enumeration feeds + their reviewed metadata-only siblings (round-21 coverage).
//
// A NeedsFilter enum op whose array ELEMENTS NEST a repository inside a content object (the repo
// location is e.g. `$[].repository.full_name` / `$[].payload.issue.repository.full_name`, NOT the
// element-root `$[].full_name`) falls into one of two classes:
//
//   - CONTENT feed (contentEnumResourceOps): the element exposes a per-repo CONTENT resource (issue/PR
//     bodies, code, commits, workflow-run/check-suite data, notification subjects). The proxy's
//     per-resource keep-gate (round-18 D / round-20) is fed classified.Resource — which degenerates to
//     "" / ResourceUnknown / a wrong key for several of these — so without an explicit content tag a
//     base=read + <resource>=none carve-out LEAKS the content. Each is tagged with its content key.
//
//   - METADATA feed (metadataNestedRepoEnumOps): the nested repo is just the repository the codespace /
//     package / alert / invitation / advisory belongs to — gating it at base (metadata) is correct, and
//     for the alert feeds there is no finer per-repo resource key (base=none hides them, base=read
//     includes them — the documented round-19 residual).
//
// EVERY nests-a-repo enum op MUST appear in exactly one of these two tables; TestCoverage_NestedRepoEnumOps
// (coverage_invariant_test.go) re-derives the nests-a-repo set from the generated repoEnumOps and fails
// the BUILD on an unclassified one, so content feeds in the embedded spec cannot silently
// default to a metadata-only gate and leak. THIS replaces the
// per-round hand-chasing of content-feed siblings with a spec-coupled invariant.
var contentEnumResourceOps = map[string]string{
	// issue feeds (title+body; GitHub "issues" feeds also carry PRs — the same heterogeneity imprecision
	// accepted since round-18-D).
	"/issues":                             "issues",
	"/user/issues":                        "issues",
	"/orgs/{org}/issues":                  "issues",
	"/repos/{owner}/{repo}/issues":        "issues",
	"/repos/{owner}/{repo}/issues/events": "issues",
	"/repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocked_by": "issues",
	"/repos/{owner}/{repo}/issues/{issue_number}/dependencies/blocking":   "issues",
	"/repos/{owner}/{repo}/issues/{issue_number}/sub_issues":              "issues",
	"/search/issues": "issues",
	// notification subjects expose issue/PR titles.
	"/notifications":                      "issues",
	"/notifications/threads/{thread_id}":  "issues",
	"/repos/{owner}/{repo}/notifications": "issues",
	// code / commit search.
	"/search/code":    "contents",
	"/search/commits": "commits",
	// workflow runs (actions data) and check suites (checks data); the classifier gives "actions"/"commits"
	// from the path, but check-suites under a /commits/ path must gate on "checks" not "commits".
	"/repos/{owner}/{repo}/actions/runs":                         "actions",
	"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs": "actions",
	"/repos/{owner}/{repo}/commits/{ref}/check-suites":           "checks",
	// activity-event feeds (payload.issue / payload.comment / payload.pull_request content — round-21).
	"/events":                                  "issues",
	"/networks/{owner}/{repo}/events":          "issues",
	"/orgs/{org}/events":                       "issues",
	"/repos/{owner}/{repo}/events":             "issues",
	"/users/{username}/events":                 "issues",
	"/users/{username}/events/public":          "issues",
	"/users/{username}/events/orgs/{org}":      "issues",
	"/users/{username}/received_events":        "issues",
	"/users/{username}/received_events/public": "issues",
}

// metadataNestedRepoEnumOps are nests-a-repo enum ops whose nested repository is metadata only — the
// repo a codespace/package/invitation/advisory belongs to, or an org-scoped alert/repo-list feed with
// no finer per-repo resource key. Gating each at base (metadata) is correct; they are listed (not just
// omitted) so the coverage invariant can tell a reviewed metadata feed from an UNclassified one. The
// boolean is always true; the value carries the review reason for the reader.
var metadataNestedRepoEnumOps = map[string]string{
	// codespaces — the repo the codespace is for.
	"/orgs/{org}/codespaces":                    "codespace's repository (metadata)",
	"/orgs/{org}/members/{username}/codespaces": "codespace's repository (metadata)",
	"/repos/{owner}/{repo}/codespaces":          "codespace's repository (metadata)",
	"/user/codespaces":                          "codespace's repository (metadata)",
	// packages — the repo the package belongs to.
	"/orgs/{org}/packages":       "package's repository (metadata)",
	"/user/packages":             "package's repository (metadata)",
	"/users/{username}/packages": "package's repository (metadata)",
	// docker conflicts — the repos involved (metadata).
	"/orgs/{org}/docker/conflicts":       "docker-conflict repository (metadata)",
	"/user/docker/conflicts":             "docker-conflict repository (metadata)",
	"/users/{username}/docker/conflicts": "docker-conflict repository (metadata)",
	// invitations — the repo the invite is for.
	"/repos/{owner}/{repo}/invitations": "repository invitation's repository (metadata)",
	"/user/repository_invitations":      "repository invitation's repository (metadata)",
	// alert feeds — alert content gated at base; no per-repo alert resource key exists (base=none hides,
	// base=read includes — the documented round-19 residual).
	"/orgs/{org}/secret-scanning/alerts":          "alert feed gated at base (no per-repo alert key — round-19 residual)",
	"/orgs/{org}/dependabot/alerts":               "alert feed gated at base (no per-repo alert key — round-19 residual)",
	"/orgs/{org}/code-scanning/alerts":            "alert feed gated at base (no per-repo alert key — round-19 residual)",
	"/enterprises/{enterprise}/dependabot/alerts": "alert feed gated at base (no per-repo alert key — round-19 residual)",
	// security advisories — the private fork repo (metadata; whole advisory over-dropped if the fork is denied).
	"/orgs/{org}/security-advisories":           "advisory private_fork repository (metadata)",
	"/repos/{owner}/{repo}/security-advisories": "advisory private_fork repository (metadata)",
	// code-security config repo lists (metadata).
	"/enterprises/{enterprise}/code-security/configurations/{configuration_id}/repositories": "config's repository list (metadata)",
	"/orgs/{org}/code-security/configurations/{configuration_id}/repositories":               "config's repository list (metadata)",
	// CodeQL variant-analysis repo names (metadata; names redacted, counts decremented — round-19/21).
	"/repos/{owner}/{repo}/code-scanning/codeql/variant-analyses/{codeql_variant_analysis_id}": "variant-analysis scanned/skipped repo names (metadata)",
	// starred repos (metadata repo list, incl. star+json repo).
	"/users/{username}/starred": "starred repository (metadata)",
	// GitHub Classroom — assignment repos / classroom name (metadata / education API).
	"/assignments/{assignment_id}/accepted_assignments": "classroom assignment repository (metadata)",
	"/classrooms/{classroom_id}/assignments":            "classroom name location (education API; metadata)",
}

type contentResourceTemplate struct {
	tmpl     opTemplate
	resource string
}

var contentResourceTemplates []contentResourceTemplate

func init() {
	for path, res := range contentEnumResourceOps {
		contentResourceTemplates = append(contentResourceTemplates, contentResourceTemplate{
			tmpl: parseTemplate(path, nil), resource: res,
		})
	}
}

// EnumContentResource returns the per-resource policy key governing the CONTENT a cross-repo content
// enumeration feed's elements expose, or "" if normPath is not a known content feed. The proxy uses it
// as the per-resource AND term so a base=read + <resource>=none carve-out is enforced on these feeds.
func EnumContentResource(normPath string) string {
	ps := segments(normPath)
	for _, t := range contentResourceTemplates {
		if t.tmpl.matches(ps) {
			return t.resource
		}
	}
	return ""
}
