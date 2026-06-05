package gqlfilter

import (
	"sort"
	"strings"
	"testing"
)

// TestR19_EventRepoPathOwnership pins the round-19 F2 fix: timeline-event types whose only
// Repository link is FOREIGN (a transfer source, the referencing commit, a cross-repo issue
// relation, a head-side fork commit) must NOT derive a repo path through that foreign link.
// Either they derive through their OWN link (the destination issue / the PR's base repo) or they
// fall to repoOwnedNoPath (ambient-attributed + node-denied), never to a foreign repo.
func TestR19_EventRepoPathOwnership(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	firstHop := func(typ string) string {
		p := s.repoPath[typ]
		if len(p) == 0 {
			return ""
		}
		return p[0].field
	}

	// Types that must fall to repoOwnedNoPath (no own-repo path): their sole link is cross-repo.
	mustNoPath := []string{
		"ReferencedEvent",
		"SubIssueAddedEvent", "SubIssueRemovedEvent",
		"BlockedByAddedEvent", "BlockedByRemovedEvent",
		"BlockingAddedEvent", "BlockingRemovedEvent",
	}
	for _, typ := range mustNoPath {
		if s.schema.Types[typ] == nil {
			continue // schema refresh removed it; nothing to assert
		}
		if s.repoScoped[typ] {
			t.Errorf("%s is repoScoped via %q but its only repo link is FOREIGN; expected repoOwnedNoPath", typ, firstHop(typ))
		}
		if !s.repoOwnedNoPath[typ] {
			t.Errorf("%s must be repoOwnedNoPath (ambient-attributed + node-denied), got neither bucket", typ)
		}
	}

	// Types that must derive through their OWN link, not the foreign one.
	mustOwn := map[string]string{
		"TransferredEvent":          "issue",       // destination issue, not fromRepository
		"HeadRefForcePushedEvent":   "pullRequest", // base repo, not the fork's afterCommit
		"PullRequestRevisionMarker": "pullRequest", // PR's repo, not lastSeenCommit (possible fork)
	}
	for typ, want := range mustOwn {
		if s.schema.Types[typ] == nil {
			continue
		}
		if !s.repoScoped[typ] {
			t.Errorf("%s should be repoScoped via %q, got no path", typ, want)
			continue
		}
		if got := firstHop(typ); got != want {
			t.Errorf("%s derives repo via %q, want own-repo link %q (foreign-link misattribution)", typ, got, want)
		}
	}
}

// TestR19_NoForeignDirectRepositoryPath is the PERMANENT guard for the round-19 F2 class: no
// repo-scoped type may derive its repository through a DIRECT Repository field whose name is not
// the canonical `repository` membership. A schema refresh that introduces a new foreign direct-
// Repository link (e.g. someOtherRepository: Repository) and lets deriveRepoPaths follow it fails
// the build here instead of silently mis-attributing — and leaking — that type's data.
func TestR19_NoForeignDirectRepositoryPath(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for typ, path := range s.repoPath {
		if len(path) == 0 {
			continue
		}
		first := path[0].field
		def := s.schema.Types[typ]
		if def == nil {
			continue
		}
		for _, f := range def.Fields {
			if f.Name != first {
				continue
			}
			// A direct Repository-typed first hop must be named exactly `repository`.
			if f.Type.Elem == nil && f.Type.Name() == "Repository" && f.Name != "repository" {
				bad = append(bad, typ+"."+first)
			}
			break
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("repo-scoped types deriving through a non-canonical direct Repository link "+
			"(foreign-repo misattribution — exclude in crossRepoNavFields/crossRepoNavByType or the "+
			"direct-Repository rule in deriveRepoPaths):\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestR19_KeepShellPrunesUnmarkedIntermediate pins the round-19 F3 fix: when a repository
// container is kept leniently (KeepShell: base=none + a per-resource read grant, metadata denied),
// an UNMARKED intermediate object reached on the way to a granted (marked) descendant must have its
// OWN scalars stripped, not forwarded. Models repository(secret){ projectV2{ title readme
// items{nodes{...on Issue{title}}} } } reached by navigation, where issues=read but the project's
// own title/readme is base/metadata data the direct path denies.
func TestR19_KeepShellPrunesUnmarkedIntermediate(t *testing.T) {
	const denied = "acme/secret"
	// authorize mirrors the proxy's filterGraphQLResponse callback for a base=none + issues=read repo.
	authorize := func(owner, repo, resource, typename string) Decision {
		if owner+"/"+repo != denied {
			return Keep
		}
		if typename == RepositoryContainerType {
			return KeepShell // readable via issues, but metadata denied → structural shell only
		}
		if resource == "issues" {
			return Keep
		}
		return Deny
	}
	resp := map[string]any{
		"data": map[string]any{
			"repository": map[string]any{
				markerAlias:     denied, // Repository marker (nameWithOwner string)
				markerTypeAlias: RepositoryContainerType,
				"name":          "secret", // container scalar → must be stripped
				"projectV2": map[string]any{ // UNMARKED intermediate
					"title":            "SECRET-PROJECT-TITLE",
					"readme":           "SECRET-PROJECT-README",
					"shortDescription": "SECRET-DESC",
					"items": map[string]any{
						"nodes": []any{
							map[string]any{
								markerAlias:     map[string]any{"nameWithOwner": denied},
								markerTypeAlias: "Issue",
								"title":         "granted-issue-title", // issues=read → kept
							},
						},
					},
				},
			},
		},
	}
	out := FilterWithDecision(resp, authorize)
	blob := mustJSON(out)
	for _, leak := range []string{"SECRET-PROJECT-TITLE", "SECRET-PROJECT-README", "SECRET-DESC", "\"secret\""} {
		if strings.Contains(blob, leak) {
			t.Errorf("KeepShell leaked %q via an unmarked intermediate: %s", leak, blob)
		}
	}
	if !strings.Contains(blob, "granted-issue-title") {
		t.Errorf("KeepShell wrongly dropped the granted (issues=read) descendant: %s", blob)
	}
}

// sanity: the resolve query for TransferredEvent now points at the destination issue's repo.
func TestR19_NodeResolveQueryUsesOwnLinks(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := s.NodeResolveQuery()
	// ReferencedEvent must no longer appear (it is repoOwnedNoPath → node-denied, not resolved).
	if strings.Contains(q, "on ReferencedEvent") {
		t.Errorf("node-resolve query still resolves ReferencedEvent; it must be repoOwnedNoPath (node-denied)")
	}
	// TransferredEvent, if present, must resolve via issue{repository{...}}, never fromRepository.
	if s.schema.Types["TransferredEvent"] != nil {
		if !strings.Contains(q, "on TransferredEvent{") {
			t.Errorf("node-resolve query is missing TransferredEvent")
		}
		if strings.Contains(q, "fromRepository") {
			t.Errorf("node-resolve query resolves a node via fromRepository (foreign repo)")
		}
	}
}
