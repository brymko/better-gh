package restfilter

import (
	"bytes"
	"encoding/json"
	"strings"
)

// repo-NAME-keyed map responses (hand-maintained — see below).
//
// A Pass GET can return a JSON OBJECT whose KEYS are repository names (an additionalProperties map). The
// OpenAPI generator and the ContainsDeniedRepo body-scan both inspect VALUES (full_name/repository_url/
// bare `repository` strings) and recurse children — they NEVER inspect the KEYS — so a repo named only as
// a key is invisible. The canonical case is the org Copilot content-exclusion rules:
//
//	GET /orgs/{org}/copilot/content_exclusion  →  { "<repo-name>": ["/path/glob", …], … }
//
// where each KEY is a BARE repo name (no owner) qualified by the {org} path parameter and the value is the
// repo's internal file-path exclusion globs. A client holding the org at base=read but DENIED a private
// repo otherwise learned that repo's existence + its internal directory/file patterns (round-43 F5). The
// proxy qualifies each key with the path owner and DROPS the denied ones.
//
// Maintenance: hand-maintained — a key's repo-name semantics are NOT typed in the spec, so the body-scan
// cannot derive them. TestSpecCoverage_RepoKeyedMapOps asserts every Pass GET additionalProperties-map op
// is either registered here or in the (non-repo-keyed) exempt set, so a new repo-keyed-map op fails the
// build instead of leaking.
var repoKeyedMapOps = []string{
	"/orgs/{org}/copilot/content_exclusion",
}

var repoKeyedMapTemplates []opTemplate

func init() {
	for _, p := range repoKeyedMapOps {
		repoKeyedMapTemplates = append(repoKeyedMapTemplates, parseTemplate(p, nil))
	}
}

// IsRepoKeyedMap reports whether normPath returns a JSON object whose KEYS are repository names qualified
// by the path owner (segments[1]).
func IsRepoKeyedMap(normPath string) bool {
	ps := segments(normPath)
	for _, t := range repoKeyedMapTemplates {
		if t.matches(ps) {
			return true
		}
	}
	return false
}

// RedactRepoKeyedMap drops top-level object KEYS naming a repository the policy denies. owner is the path
// owner (the {org}/{username} segment); a bare key is qualified as owner/key, an already-"owner/repo" key
// is used as-is. Fails closed (ok=false) on a non-empty unparseable body, a missing owner, or a root that
// is not a JSON object (the op's contract is a repo-keyed map). An empty body passes through.
func RedactRepoKeyedMap(body []byte, owner string, authorized func(ownerRepo string) bool) ([]byte, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, true
	}
	if owner == "" {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return nil, false
	}
	m, ok := root.(map[string]any)
	if !ok {
		return nil, false
	}
	for key := range m {
		repo := key
		if !strings.Contains(repo, "/") {
			repo = owner + "/" + repo
		}
		if strings.Count(repo, "/") != 1 || !authorized(repo) {
			delete(m, key)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return out, true
}
