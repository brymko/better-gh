package restfilter

// Cross-repo CONTENT enumeration feeds (hand-maintained — see below).
//
// A NeedsFilter enum op whose array ELEMENTS expose a specific repo CONTENT resource (issue/PR
// bodies, code fragments, commits, notification subjects) rather than just repository metadata.
// These feeds classify to an UNSCOPED category (search/user) or to nothing (/issues), so the
// proxy hands the per-resource keep-gate (round-18 D) classified.Resource — which is "" for them.
// With resource=="" the gate degenerates to a metadata-only check (policy.Evaluate skips the
// per-resource branch for a read with an empty resource and falls to base access), so a
// [[repo]] base=read + <resource>=none carve-out LEAKS its content through the feed: GET
// /user/issues / /issues / /search/issues return the title+body of a repo whose issues=none, and
// /search/code returns its code, even though the direct GET /repos/{o}/{r}/issues|contents is 403.
// This is the non-path-scoped sibling of the round-18-D /orgs/{org}/issues fix (round-20).
//
// Tagging each feed with its content resource makes the keep-gate AND that resource, so the
// carve-out is enforced on these feeds exactly as orgResource does for /orgs/{org}/issues.
//
// Note on heterogeneity: GitHub's "issues" feeds and notifications also surface pull requests; like
// round-18-D's /orgs/{org}/issues they are gated on "issues" (a PR riding an issues feed is kept iff
// issues is readable), which is the pre-existing accepted imprecision, not a regression.
//
// Maintenance: hand-maintained like the scrub tables. A feed absent here defaults to "" → the
// metadata gate, which is CORRECT for repo-ENUMERATION feeds (/user/repos, packages, codespaces:
// the element IS a repository, so metadata is the right gate) but a fail-OPEN for any NEW content
// feed. When refreshing against a new spec, audit repoEnumOps for ops whose element NESTS a
// repository (a content object that has a repo, not a repo object) and add them here.
var contentEnumResourceOps = map[string]string{
	"/issues":                            "issues",
	"/user/issues":                       "issues",
	"/orgs/{org}/issues":                 "issues",
	"/search/issues":                     "issues",
	"/search/code":                       "contents",
	"/search/commits":                    "commits",
	"/notifications":                     "issues",
	"/notifications/threads/{thread_id}": "issues",
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
// enumeration feed's elements expose (issues feeds → "issues", code search → "contents", commit
// search → "commits", notifications → "issues"), or "" if normPath is not such a feed. The proxy
// uses it as the per-resource AND term when redacting these feeds so a base=read + <resource>=none
// carve-out is enforced even though the classifier scoped the request to an unscoped category.
func EnumContentResource(normPath string) string {
	ps := segments(normPath)
	for _, t := range contentResourceTemplates {
		if t.tmpl.matches(ps) {
			return t.resource
		}
	}
	return ""
}
