package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/auth"
	"better-gh/internal/classifier"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
	"better-gh/internal/restfilter"
	"better-gh/internal/store"
)

type ListenerMode int

const (
	SocketMode ListenerMode = iota
	GHEMode
)

func (m ListenerMode) String() string {
	if m == GHEMode {
		return "ghe"
	}
	return "socket"
}

type Handler struct {
	GithubToken  string        // static custodian token (fallback / tests)
	Custodian    func() string // dynamic custodian; overrides GithubToken when set (captured via sign-in)
	Store        *store.Store
	Audit        *audit.Logger
	Client       *http.Client
	Mode         ListenerMode
	SocketPolicy *policy.Policy // used for socket mode when no proxy token matches
	NodeCache    *nodecache.Cache
	GQLFilter    *gqlfilter.Schema // schema-aware GraphQL response filter (read isolation)
	UpstreamURL  string            // default "" → "https://api.github.com"
}

// custodianToken is the GitHub token the proxy forwards with: the dynamic Custodian (the
// token captured by the owner's sign-in) when set, else the static GithubToken.
func (h *Handler) custodianToken() string {
	if h.Custodian != nil {
		return h.Custodian()
	}
	return h.GithubToken
}

const maxBodySize = 10 << 20 // 10 MB

// hopByHopOrManaged headers are not copied from the client to the upstream request:
// the client's Authorization is replaced with the real token, Host/Content-Length are
// recomputed, X-GitHub-Api-Version is pinned, and the rest are hop-by-hop.
//
// Accept-Encoding is intentionally dropped: if it were forwarded, Go's transport would
// hand back the still-compressed upstream body (it only auto-decompresses responses to
// gzip requests IT added). The GraphQL response filter cannot parse a gzipped body, so it
// would fail open and forward denied-repo data unredacted; plain responses would also be
// corrupted (Content-Encoding is stripped on the way back). Dropping it lets the transport
// negotiate + transparently decompress, so the filter always sees JSON and clients get an
// identity-encoded body.
var hopByHopOrManaged = map[string]bool{
	"Authorization":        true,
	"Host":                 true,
	"Content-Length":       true,
	"Accept-Encoding":      true,
	"X-Github-Api-Version": true,
	"Connection":           true,
	"Proxy-Connection":     true,
	"Keep-Alive":           true,
	"Transfer-Encoding":    true,
	"Te":                   true,
	"Trailer":              true,
	"Upgrade":              true,
	// Cookie is a browser-managed header the upstream GitHub API never needs; forwarding it would
	// send a client's cookies (e.g. the loginflow bgh_grant browser-binding secret, set Path=/ and
	// thus attached to same-origin proxy API requests) upstream under the real custodian token. The
	// proxy strips Set-Cookie on responses (round-18); strip Cookie on requests symmetrically (round-20).
	"Cookie": true,
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := r.URL.Path

	authHeader := r.Header.Get("Authorization")
	clientToken := auth.ExtractToken(authHeader)

	if h.Mode == GHEMode && clientToken == "" {
		jsonError(w, http.StatusUnauthorized, "bgh: unauthorized")
		return
	}

	// Only GHE mode authenticates against the proxy-token store. Socket mode trusts the
	// local user and ALWAYS applies the single SocketPolicy: a proxy token presented over
	// the socket must not silently swap in a different (possibly broader) policy, and gh's
	// own GitHub token isn't in the store anyway.
	var proxyToken *store.ProxyToken
	if h.Mode == GHEMode {
		proxyToken = h.Store.Lookup(clientToken)
		if proxyToken == nil {
			jsonError(w, http.StatusUnauthorized, "bgh: unauthorized")
			return
		}
	}

	if h.Mode == GHEMode && classifier.IsGHEAuthEndpoint(r.Method, path) {
		norm := classifier.NormalizePath(path)
		if norm == "/" || norm == "" {
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
			return
		}
	}

	norm := classifier.NormalizePath(path)
	// Synthetic identity ONLY for GET (gh auth status). A non-GET /user (e.g. PATCH to update the
	// authenticated user) must be classified + policy-checked, not short-circuited to a fake 200.
	if h.Mode == GHEMode && r.Method == http.MethodGet && (norm == "/user" || norm == "/user/") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"login":"bgh-proxy","id":0}`))
		return
	}

	if classifier.HasDotSegment(path) {
		jsonError(w, http.StatusBadRequest, "bgh: invalid path")
		return
	}

	// Read one byte past the cap so an over-limit body is REJECTED, not silently
	// truncated: a truncated body would be classified and forwarded as a corrupted write
	// (and a truncated GraphQL body would mis-parse). 413 is clearer and safe.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bgh: failed to read request body")
		return
	}
	if len(body) > maxBodySize {
		jsonError(w, http.StatusRequestEntityTooLarge, "bgh: request body too large")
		return
	}

	classified := classifier.Classify(r.Method, path, body)

	tokenName := ""
	var pol *policy.Policy

	if proxyToken != nil {
		tokenName = proxyToken.Name
		pol = &proxyToken.Policy
	} else if h.Mode == SocketMode && h.SocketPolicy != nil {
		tokenName = "(socket)"
		pol = h.SocketPolicy
	} else {
		durationMs := time.Since(start).Milliseconds()
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             path,
			Repo:             classified.RepoFullName(),
			Org:              classified.Org,
			Resource:         classified.Resource,
			UnscopedCategory: classified.UnscopedCategory,
			Access:           classified.Access.String(),
			PolicyResult:     "denied: no token provided",
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
		})
		jsonError(w, http.StatusForbidden, "bgh: denied — no token provided")
		return
	}

	// A request can address objects by opaque node ID with no repository() scope —
	// mutation inputs, and node(id:)/nodes(ids:) reads. Resolve every referenced node
	// ID to its REAL repository (authoritatively, via GitHub) and add those as scopes,
	// so a node-ID request cannot reach a repo the token can't access. Unresolvable
	// nodes fail closed. Gated on AllowsAny{Write,Read} so a token that can never act
	// at this access level cannot burn the upstream rate limit on doomed resolves.
	forceDenyReason := ""
	if h.NodeCache != nil && len(classified.NodeIDs) > 0 &&
		(norm == "/graphql" || norm == "/graphql/") {
		canResolve := pol.AllowsAnyWrite()
		if classified.Access == classifier.Read {
			canResolve = pol.AllowsAnyRead()
		}
		if !canResolve {
			forceDenyReason = "node-scoped request not permitted by policy"
		} else if scopes, ok := h.resolveNodeScopes(r.Context(), classified.NodeIDs, classified.NodeIDResource, classified.Access); ok {
			// Each resolved node carries the resource of the root mutation field that
			// referenced it (mergePullRequest → "pulls", createIssue → "issues"), so a
			// per-resource permission applies per the operation that actually touches the
			// repo — a multi-root mutation can't smuggle a restricted-resource write under
			// the first field's resource. Reads have no per-node resource; fall back to the
			// request's primary resource so a per-resource read rule still applies.
			if classified.Access == classifier.Read {
				for i := range scopes {
					if scopes[i].Resource == "" {
						scopes[i].Resource = classified.Resource
					}
				}
			}
			// scopes can be empty when every referenced node is non-repo (e.g. a user
			// assignee); then the request carries no node-derived repo constraint.
			if len(scopes) > 0 {
				// Promote a resolved node to the PRIMARY scope only when the primary is TRULY empty.
				// A read like `{viewer{login email} node(id:$id){...}}` has an unscoped primary
				// (UnscopedCategory="user"); overwriting Owner/Repo from the node while leaving
				// UnscopedCategory dangling made evaluateScopes match the repo rule and SKIP the
				// `user` category check (policy.Evaluate only consults it when repo==""&&org==""),
				// leaking the custodian's viewer{} identity under a policy that denies `user`. With
				// UnscopedCategory!="" we fall to the else branch: node scopes are ANDed in Additional
				// and the original unscoped primary is still enforced. Mutations never set
				// UnscopedCategory, so the round-12 addComment/per-resource cases are unaffected. round-15.
				if !classified.HasRepo() && classified.Org == "" && classified.UnscopedCategory == "" {
					classified.Owner = scopes[0].Owner
					classified.Repo = scopes[0].Repo
					// Carry the resolved node's per-resource key into the PRIMARY scope too — not
					// just Additional. Otherwise the primary scope keeps the mutation's name-derived
					// Resource ("" for addComment/addReaction/…), which now fails closed under a
					// per-resource rule and would wrongly deny an allowed write (e.g. commenting on
					// an issue when issues is writable but pulls is not). round-12 audit H2/H3.
					classified.Resource = scopes[0].Resource
					classified.Additional = append(classified.Additional, scopes[1:]...)
				} else {
					classified.Additional = append(classified.Additional, scopes...)
				}
			}
		} else {
			forceDenyReason = "unresolved node id"
		}
	}

	repoName := classified.RepoFullName()

	result := evaluateScopes(pol, &classified)

	// Sound GraphQL read isolation: rewrite the query to tag every repo-scoped object
	// with its repository, then redact (from the response) any object whose repository
	// the policy denies. This is the authoritative defense against cross-repo navigation
	// the classifier can't see. When it IS in effect, the classifier's nav-escape flag
	// is ignored (the filter handles it); when it is NOT (schema drift / disabled), the
	// flag falls back to denying the whole request.
	var respFilter func([]byte) ([]byte, bool)
	// passScan, when set (a non-path-scoped REST "Pass" response), makes forward() scan the actual
	// JSON body for a denied-repo identity the static OpenAPI table did not locate, failing closed if
	// one is present — so "Pass" is not a blind fail-open for an under-typed response schema (round-16).
	var passScan func(string) bool
	if h.GQLFilter != nil && (norm == "/graphql" || norm == "/graphql/") {
		// Reads AND mutations: a mutation's payload is a read sub-graph that can navigate
		// to other repos, so its response must be filtered too. Augmentation injects the
		// repository markers; filterGraphQLResponse redacts denied repos and fails closed.
		if aug, ok := h.augmentGraphQL(body); ok {
			body = aug
			p := pol
			respFilter = func(resp []byte) ([]byte, bool) { return filterGraphQLResponse(h.GQLFilter, p, resp) }
		}
	}

	// canReadFor gates a repo entry by BOTH its `metadata` read AND the endpoint's per-resource read,
	// so a base=none repo and a base=read + <resource>=none carve-out are both dropped/scrubbed. Shared
	// by the GET/HEAD enum/scrub path and the write-response cross-ref scrub below.
	canReadFor := func(enumResource string) func(string) bool {
		return func(repo string) bool {
			owner := repo
			if i := strings.IndexByte(repo, '/'); i > 0 {
				owner = repo[:i]
			}
			if !pol.Evaluate(repo, owner, classifier.Read, "metadata", "").Allowed {
				return false
			}
			return pol.Evaluate(repo, owner, classifier.Read, enumResource, "").Allowed
		}
	}

	// REST read isolation, typed against GitHub's OpenAPI description (internal/restfilter):
	// a GET is classified as NeedsFilter (response carries repositories → redact denied ones at
	// the spec-derived locations, failing closed on an unparseable body), Pass (no repositories
	// → forward), or Unknown (off-spec path). This replaces the old hand-maintained allowlist,
	// so coverage is the whole REST surface and — like the GraphQL filter — unrecognized
	// requests fail closed instead of leaking.
	if respFilter == nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		dec, locs := restfilter.Lookup(norm)
		// Cross-reference content scrub: some responses embed a FULL foreign-repo issue/PR (title+
		// body) inside an array element via a `source` cross-reference (the issue timeline's
		// cross-referenced event). That foreign repo may be denied even though the path repo is
		// allowed, and the enum redactor can't express it (it would drop every non-cross-ref event).
		// Scrub nulls just the cross-ref sub-object per element when its repo is denied (audit F2).
		scrubLocs := restfilter.ScrubLocations(norm)
		// Bare-string repo arrays the OpenAPI generator can't locate (e.g. the CodeQL variant
		// analysis's not_found_repos.repository_full_names) — dropped by a hand-maintained table so a
		// denied repo's NAME doesn't leak (round-19 F4).
		strArrayLocs := restfilter.StringArrayLocations(norm)
		// Denied-content scrub: a few responses embed a full content object (a projectsV2 item's linked
		// issue/PR) from another repo the client referenced by node id; null it when its repo is denied,
		// so it can't be a REST sidedoor around the node(id:) content-read block (round-21).
		contentScrubFields := restfilter.ContentScrubFields(norm)
		// Gate each repo-bearing entry by BOTH the repo's own `metadata` access AND the enumerated
		// endpoint's resource, NOT the lenient CanReadAnything. Two complementary leaks:
		//   (a) base=none + a per-resource carve-out (permissions={issues="read"}) must NOT surface:
		//       its metadata is denied on the DIRECT path, so the enum/search/singleton path must drop
		//       it too. The `metadata` check covers this — CanReadAnything wrongly kept it (round-15).
		//   (b) base=read + a per-resource DENY of THIS endpoint's resource (permissions={issues="none"})
		//       must NOT surface either: GET /repos/{o}/{r}/issues is 403 (resource "issues" → deny), so
		//       the org/user-wide GET /orgs/{org}/issues enumeration must drop that repo's issues too.
		//       The `metadata`-only gate kept it (base=read passes metadata), leaking exactly the
		//       title/body issues=none was meant to hide. ANDing the endpoint's resource (classified
		//       .Resource — the per-repo resource the DIRECT path would gate on: "issues" for the issues
		//       feeds, the org segment otherwise) closes it. For endpoints whose resource is "metadata"
		//       or an unmapped/ResourceUnknown segment (most alert/package/codespace feeds), the resource
		//       check degenerates to the base grant — identical to metadata — so this never over-denies.
		// A fully-denied repo (no matching rule under mode=deny) still evaluates to deny → dropped.
		enumResource := classified.Resource
		// Cross-repo CONTENT feeds (e.g. /user/issues, /issues, /search/issues, /search/code) classify
		// to an unscoped category, so classified.Resource is "" and the per-resource keep-gate below
		// would degenerate to a metadata-only check — leaking a [[repo]] base=read + <resource>=none
		// carve-out through the feed (the non-path-scoped sibling of the round-18-D /orgs/{org}/issues
		// fix — round-20). Derive the feed's content resource so the carve-out is enforced here too.
		if er := restfilter.EnumContentResource(norm); er != "" {
			enumResource = er
		}
		canRead := canReadFor(enumResource)
		switch {
		case dec == restfilter.NeedsFilter || len(scrubLocs) > 0 || len(strArrayLocs) > 0 || len(contentScrubFields) > 0:
			// Redact denied enum entries (drop), scrub embedded foreign cross-ref content (null in
			// place), drop denied bare-string repo names, null denied linked content; all fail closed on
			// an unparseable body.
			respFilter = func(resp []byte) ([]byte, bool) {
				out := resp
				if dec == restfilter.NeedsFilter {
					var ok bool
					if out, ok = restfilter.Redact(out, locs, canRead); !ok {
						return nil, false
					}
				}
				if len(scrubLocs) > 0 {
					var ok bool
					if out, ok = restfilter.Scrub(out, scrubLocs, canRead); !ok {
						return nil, false
					}
				}
				if len(strArrayLocs) > 0 {
					var ok bool
					if out, ok = restfilter.DropRepoStrings(out, strArrayLocs, canRead); !ok {
						return nil, false
					}
				}
				if len(contentScrubFields) > 0 {
					var ok bool
					if out, ok = restfilter.ScrubDeniedContent(out, contentScrubFields, canRead); !ok {
						return nil, false
					}
				}
				return out, true
			}
		case dec == restfilter.Unknown:
			// Off-spec endpoint. If the classifier already scoped it to one repository, that
			// path scope is the authorization (e.g. an unrecognized /repos/{o}/{r}/… subpath
			// about an allowed repo) — forward. Otherwise it could enumerate across repos with
			// a shape we cannot redact, and (in the default deployment) nothing behind us would
			// catch it — so fail closed. Applies to GET and HEAD alike (the enclosing block
			// already restricts to those): HEAD must not slip past the GET fail-closed and serve
			// a denied endpoint's headers as an existence/metadata oracle (audit F7).
			if result.Allowed && !classified.HasRepo() {
				result = policy.Result{Reason: "off-spec REST endpoint cannot be repo-filtered (fail closed)"}
			}
		case dec == restfilter.Pass && !classified.HasRepo():
			// "Pass" means the OpenAPI table located NO repository in this op's response — but a
			// response schema the generator could not fully type (untyped/opaque/cyclic) may still
			// carry a repo it never emitted a location for. For a non-path-scoped (enumeration-shaped)
			// response we cannot bound which repos it touches, so rather than forward it blind, have
			// forward() scan the ACTUAL body for a denied repo and fail closed if one is present
			// (round-16). Only JSON bodies are scanned — binary downloads (archives, raw blobs) stream
			// untouched — and path-scoped Pass responses keep streaming (authorized by their repo
			// scope; cross-ref embeds handled by the scrub table), so the hot path (contents/blobs) is
			// unaffected.
			//
			// EXCEPT two shapes the body-scan cannot map:
			//   - an OPAQUE NUMERIC repo id (the Copilot agent-task lookups /agents/tasks[/{id}]):
			//     ContainsDeniedRepo can't map a numeric id, so it fails closed (round-20).
			//   - a bare {id,name} repo array qualified by the path org (/orgs/{org}/attestations/
			//     repositories): the name has no owner, so it is redacted with the path owner instead.
			switch {
			case restfilter.HasOpaqueRepoID(norm):
				if result.Allowed {
					result = policy.Result{Reason: "endpoint identifies repositories only by opaque id; cannot be repo-filtered (fail closed)"}
				}
			case restfilter.IsOrgNamedRepoArray(norm):
				owner := classified.Org
				if owner == "" {
					owner = classified.Owner
				}
				respFilter = func(resp []byte) ([]byte, bool) {
					return restfilter.RedactOrgNamedRepos(resp, owner, canRead)
				}
			default:
				passScan = canRead
			}
		}
	}

	// Write responses echo the SAME foreign-repo cross-reference objects as their GET siblings (a PR's
	// head/base.repo from a fork, a repo's parent/source/template_repository), but the GET/HEAD-gated
	// block above never runs for writes — so PATCH /repos/{o}/{r}/pulls/{n} streamed a denied fork's
	// metadata unredacted (round-20). Run the cross-ref scrub (only) on write responses too; enum
	// redaction / passScan stay GET-only since a write is single-repo-scoped by the classifier and the
	// scrub merely nulls the foreign sub-object, keeping the authorized write result. (GraphQL writes
	// already have respFilter set and are skipped by the respFilter==nil guard.)
	if respFilter == nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		wlocs := restfilter.WriteScrubLocations(norm)
		// A write response can also embed a full content object (a projectsV2 item's linked issue/PR)
		// from a repo the client referenced by node id — null it when denied (round-21).
		cfields := restfilter.ContentScrubFields(norm)
		if len(wlocs) > 0 || len(cfields) > 0 {
			canRead := canReadFor(classified.Resource)
			respFilter = func(resp []byte) ([]byte, bool) {
				out := resp
				if len(wlocs) > 0 {
					var ok bool
					if out, ok = restfilter.Scrub(out, wlocs, canRead); !ok {
						return nil, false
					}
				}
				if len(cfields) > 0 {
					var ok bool
					if out, ok = restfilter.ScrubDeniedContent(out, cfields, canRead); !ok {
						return nil, false
					}
				}
				return out, true
			}
		}
	}

	// Fallback when the filter is DISABLED entirely (GQLFilter == nil, e.g. tests): rely on
	// the classifier's cross-repo-nav denylist to deny navigating requests.
	if result.Allowed && classified.NavEscapes && respFilter == nil {
		result = policy.Result{Reason: "cross-repo navigation without a response filter"}
	}
	// A GraphQL request is fully filtered or denied — never forwarded unfiltered. When the
	// filter is configured but could not type this request (schema drift: a field newer than
	// the embedded schema; or an invalid / reserved-alias query), respFilter is nil and no
	// response can be redacted, so fail closed. Relying instead on the classifier's nav
	// denylist was unsound: it is not complete (e.g. associatedPullRequests, task-list refs),
	// so an untyped scoped read could navigate cross-repo through a non-listed field and be
	// streamed unredacted. A request that types fine has a respFilter and is unaffected.
	if result.Allowed && h.GQLFilter != nil && respFilter == nil &&
		(norm == "/graphql" || norm == "/graphql/") {
		result = policy.Result{Reason: "graphql request could not be typed against the embedded schema"}
	}

	if forceDenyReason != "" || !result.Allowed {
		reason := forceDenyReason
		if reason == "" {
			reason = result.Reason
		}
		durationMs := time.Since(start).Milliseconds()
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             path,
			Repo:             repoName,
			Org:              classified.Org,
			Resource:         classified.Resource,
			UnscopedCategory: classified.UnscopedCategory,
			Access:           classified.Access.String(),
			PolicyResult:     "denied: " + reason,
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
			TokenName:        tokenName,
		})
		jsonError(w, http.StatusForbidden, "bgh: denied")
		return
	}

	if proxyToken != nil {
		go h.Store.TouchLastUsed(proxyToken.ID)
	}

	h.forward(w, r, start, norm, body, pol, proxyToken, &classified, respFilter, passScan)
}

func (h *Handler) augmentGraphQL(body []byte) ([]byte, bool) {
	var req map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil {
		return nil, false
	}
	var query string
	if json.Unmarshal(req["query"], &query) != nil || query == "" {
		return nil, false
	}
	aug, err := h.GQLFilter.Augment(query)
	if err != nil {
		// Untypable against our schema snapshot (or invalid) — forward verbatim; the
		// classifier's cross-repo-nav denylist still applies as a fallback.
		slog.Debug("graphql augment skipped", "err", err)
		return nil, false
	}
	qb, _ := json.Marshal(aug)
	req["query"] = qb
	out, err := json.Marshal(req)
	if err != nil {
		return nil, false
	}
	return out, true
}

// filterGraphQLResponse redacts denied-repo objects from a GraphQL JSON response. It
// FAILS CLOSED: if the body cannot be parsed as JSON or re-marshaled — so redaction
// cannot be applied — it returns ok=false and the caller must not forward the bytes.
// (This is why the proxy drops Accept-Encoding upstream: a gzipped body would otherwise
// be unparseable here and, before, was forwarded unredacted.)
func filterGraphQLResponse(s *gqlfilter.Schema, pol *policy.Policy, resp []byte) ([]byte, bool) {
	// UseNumber so integers beyond float64's 53-bit mantissa (large databaseIds, counts)
	// round-trip exactly: decoding to the default float64 and re-marshaling would corrupt
	// them (and reformat, e.g. 1e21). json.Number re-marshals as the original literal, and
	// the filter never interprets numbers (only string markers), so this is purely lossless.
	dec := json.NewDecoder(bytes.NewReader(resp))
	dec.UseNumber()
	var parsed map[string]any
	if dec.Decode(&parsed) != nil {
		return nil, false
	}
	// Per-resource aware: evaluate each repo-scoped object against its (repo, resource) so a
	// restriction like pulls="none" is enforced wherever the object appears — including via
	// navigation back to the same readable repo, which the repo-granular check could not catch.
	//
	// The repository CONTAINER (and only it) is kept whenever the repo is readable in ANY way:
	// redacting the container would null the allowed CHILD objects inside it, breaking a
	// base="none" + per-resource "read" grant (e.g. "read only this repo's issues"). Per-resource
	// restrictions are enforced on the specific child objects (pulls/issues/…) below.
	//
	// EVERY OTHER repo-scoped object — including content types that map to "metadata" because they
	// have no dedicated resource key (Discussion/Milestone/Project/Tag/…) — must satisfy its
	// (repo, resource) like the DIRECT path does. Applying the lenient CanReadAnything to those
	// metadata-class CONTENT leaves let cross-repo navigation forward a base="none" repo's
	// discussion/milestone/project bodies under any non-none per-resource carve-out (audit F1):
	// the direct request repository(secret){discussions{body}} is denied (its "metadata" scope
	// hits the strict Evaluate branch), so the navigated path must be denied identically. A
	// fully-denied repo is not readable in any way, so its container — and everything in it — is
	// still redacted.
	filtered := gqlfilter.FilterWithDecision(parsed, func(owner, repo, resource, typename string) gqlfilter.Decision {
		full := owner + "/" + repo
		if typename == gqlfilter.RepositoryContainerType {
			// The repository CONTAINER is kept whenever the repo is readable in ANY way, so a
			// base="none" + per-resource grant doesn't lose its granted children. But if the repo's
			// own "metadata" resource is denied, keep it only as a STRUCTURAL shell: strip its own
			// scalars + non-repo-scoped leaf content (description/sshUrl/contributingGuidelines/…),
			// which the direct request repository(secret){description} is denied — so navigating
			// back to the container can't leak them either (audit F3).
			if !pol.CanReadAnything(full, owner) {
				return gqlfilter.Deny
			}
			if pol.Evaluate(full, owner, classifier.Read, "metadata", "").Allowed {
				return gqlfilter.Keep
			}
			return gqlfilter.KeepShell
		}
		// A bare-repositoryName repo-identity type (RepositoryMigration) is an ORG-level record naming a
		// DIFFERENT repository than its enclosing marked ancestor, so the round-20 ambient attribution is
		// unsound — reached via repository(){owner{...on Organization{repositoryMigrations}}} it would be
		// kept against the allowed outer repo and leak a denied repo's name/migration metadata. Redact it
		// unconditionally (round-21), matching the node(id:) and organization-root fail-closed paths.
		if s.IsBareNameRepoIdentityType(typename) {
			return gqlfilter.Deny
		}
		// A repo-marked object whose runtime __typename the embedded schema does NOT recognize is live
		// schema drift (GitHub ahead of the snapshot): FilterResource would default it to "metadata"
		// (base), under-enforcing its possibly-stricter real resource. Mirror the node resolver's drift
		// fail-closed and redact it — the accepted "schema freshness = deny" residual — rather than
		// authorize it against base access (round-20). Only fires for genuinely unrecognized runtime types
		// (typename=="" maps to metadata by design and is unaffected).
		if typename != "" && !s.IsKnownObjectType(typename) {
			return gqlfilter.Deny
		}
		// Derive the per-resource key from the object's runtime type via the schema's @docsCategory
		// (FilterResource), NOT the incomplete value the filter passes in: this enforces per-resource
		// policy (deployments/actions/pulls/issues/branches="none") on EVERY object whose category is
		// a real resource — Environment, WorkflowRun, Milestone, Label, PullRequestThread,
		// branchProtectionRules, … — which an older ~30-entry hand map silently treated as "metadata"
		// (base access) and leaked over GraphQL (round-15).
		resource = s.FilterResource(typename)
		if pol.Evaluate(full, owner, classifier.Read, resource, "").Allowed {
			return gqlfilter.Keep
		}
		return gqlfilter.Deny
	})
	// GitHub returns partial-failure errors and warnings in PARALLEL top-level arrays the data-side
	// marker filter never touches: errors[].message / extensions.* are free-form strings with NO marker,
	// so a "no permission to view pull requests in secretcorp/private-upstream" message (a fork's denied
	// private parent, a navigated repo, …) rides out unredacted right beside the data the filter correctly
	// nulled (round-25). Scrub any string in those channels that names a repository the policy cannot read
	// in any way, replacing it wholesale (fail-closed) so a denied repo's identity/existence does not leak.
	deniedRepo := func(ownerRepo string) bool {
		i := strings.IndexByte(ownerRepo, '/')
		if i <= 0 || i >= len(ownerRepo)-1 {
			return false
		}
		return !pol.CanReadAnything(ownerRepo, ownerRepo[:i])
	}
	if errs, ok := filtered["errors"]; ok {
		filtered["errors"] = scrubDeniedRepoStrings(errs, deniedRepo)
	}
	if ext, ok := filtered["extensions"]; ok {
		filtered["extensions"] = scrubDeniedRepoStrings(ext, deniedRepo)
	}
	// Enforce org/enterprise policy on owner-private data (members + admin/billing/settings) reached by ANY
	// navigation path, not just an org/user/enterprise root the classifier scopes: a base-denied owner is
	// reduced to public identity and a members-denied owner loses its member-identity fields, using the
	// owner identifier the augmenter injected (round-25/26).
	ownerDenied := func(owner, resource string) bool {
		return owner != "" && !pol.Evaluate("", owner, classifier.Read, resource, "").Allowed
	}
	filtered = gqlfilter.RedactDeniedOwnerPrivate(filtered, ownerDenied).(map[string]any)
	out, err := json.Marshal(filtered)
	if err != nil {
		return nil, false
	}
	return out, true
}

const redactedErrorMessage = "redacted by bgh: this response referenced a resource the policy denies"

// repoNameToken matches an owner/repo-shaped substring in free-form error text (GitHub's permission
// messages embed the full name, e.g. "... in secretcorp/private-upstream.").
var repoNameToken = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]+`)

// scrubDeniedRepoStrings recursively replaces any string in a GraphQL errors[]/extensions subtree that
// names a repository `denied` reports unreadable, with a generic message. Fail-closed: a name-bearing
// string is replaced WHOLESALE rather than partially patched, so a denied repo's name cannot survive.
func scrubDeniedRepoStrings(v any, denied func(ownerRepo string) bool) any {
	switch val := v.(type) {
	case string:
		for _, tok := range repoNameToken.FindAllString(val, -1) {
			if denied(tok) {
				return redactedErrorMessage
			}
		}
		return val
	case map[string]any:
		for k, c := range val {
			val[k] = scrubDeniedRepoStrings(c, denied)
		}
		return val
	case []any:
		for i, c := range val {
			val[i] = scrubDeniedRepoStrings(c, denied)
		}
		return val
	}
	return v
}

// evaluateScopes allows a request only if EVERY scope it touches is allowed. A
// single GraphQL document may reference several repositories/orgs at once; checking
// only the primary scope would let a denied repo ride along (see classifier.Result).
func evaluateScopes(pol *policy.Policy, c *classifier.Result) policy.Result {
	for _, s := range c.AllScopes() {
		repo := ""
		if s.Owner != "" && s.Repo != "" {
			repo = s.Owner + "/" + s.Repo
		}
		org := s.Org
		if org == "" {
			org = s.Owner
		}
		if res := pol.Evaluate(repo, org, c.Access, s.Resource, s.UnscopedCategory); !res.Allowed {
			return res
		}
	}
	return policy.Result{Allowed: true}
}

// maxResolveIDs caps how many node IDs one mutation may reference. GitHub's
// nodes(ids:) accepts at most 100; beyond that the resolve would fail anyway, so we
// reject up front rather than build an oversized upstream query.
const maxResolveIDs = 100

// node resolution outcomes for a single ID.
const (
	nodeSkip = iota // null (invalid/unknown/no-access to the upstream token) or a non-repo node → no constraint
	nodeRepo        // belongs to a repository → must be policy-checked
	nodeDeny        // resolved to a repo-scoped TYPE but GitHub returned no repository → fail closed
)

type nodeRes struct {
	kind        int
	owner, repo string
	typename    string // resolved GraphQL __typename, used to derive the per-resource key
}

// resolveNodeScopes maps each referenced node ID to the repository GitHub says it belongs
// to. Repo-scoped nodes become Scopes the policy must allow. A node that does not resolve
// (invalid/unknown, or not visible to the upstream token) and a non-repo node (user, org)
// add no constraint and are skipped — a node the upstream token cannot resolve it cannot
// mutate either, so this cannot exceed policy; a *lone* such node leaves the request with
// no repo scope, which the policy denies as an unscoped write. Only a node that resolves
// to a repo-scoped TYPE without a repository (anomalous) fails the whole request closed.
// An upstream error also fails closed. Returns (scopes, ok); scopes may be empty.
func (h *Handler) resolveNodeScopes(ctx context.Context, ids []string, resourceByID map[string][]string, access classifier.AccessLevel) ([]classifier.Scope, bool) {
	if len(ids) > maxResolveIDs {
		return nil, false
	}
	type resolved struct{ owner, repo, typename string }
	repoOf := make(map[string]resolved, len(ids))
	var missing []string
	for _, id := range ids {
		// WRITE path: never trust the cache — always re-resolve against GitHub. A cached
		// node→repo mapping goes stale if the object's repository is TRANSFERRED within the 30-min
		// TTL, which would otherwise authorize the write against the node's PRE-transfer repository
		// (round-15). Reads keep using the cache: a stale read attribution is moot because the
		// response is redacted against the object's actual repository marker, not the cache.
		if access != classifier.Write {
			if owner, repo, typename, ok := h.NodeCache.Get(id); ok {
				repoOf[id] = resolved{owner, repo, typename} // cache only ever holds verified repo nodes
				continue
			}
		}
		missing = append(missing, id)
	}

	if len(missing) > 0 {
		fetched, err := h.resolveFromGitHub(ctx, missing)
		if err != nil {
			slog.Error("node resolution failed", "err", err)
			return nil, false
		}
		for _, id := range missing {
			switch fetched[id].kind { // absent → zero value nodeSkip → ignored
			case nodeRepo:
				h.NodeCache.Put(id, fetched[id].owner, fetched[id].repo, fetched[id].typename)
				repoOf[id] = resolved{fetched[id].owner, fetched[id].repo, fetched[id].typename}
			case nodeDeny:
				return nil, false // repo-scoped type without a repository → fail closed
			}
		}
	}

	scopes := make([]classifier.Scope, 0, len(repoOf))
	for _, id := range ids {
		r, ok := repoOf[id]
		if !ok {
			continue
		}
		// One scope per DISTINCT resource the node was referenced under, so a shared repository node
		// used by two root mutation fields (issues + branches) is policy-checked for BOTH (round-24).
		resources := resourceByID[id]
		if len(resources) == 0 {
			resources = []string{""}
		}
		for _, res := range resources {
			for _, key := range h.nodeResourceKeys(access, r.typename, res) {
				scopes = append(scopes, classifier.Scope{Owner: r.owner, Repo: r.repo, Resource: key})
			}
		}
	}
	return scopes, true
}

// nodeResourceKeys returns the per-resource key(s) a resolved node must satisfy. For a WRITE it emits
// the UNION of the mutation field-name guess AND the node's REAL type-derived resource, requiring the
// policy to allow BOTH (every scope is ANDed). This closes two symmetric dodges:
//   - name="" addressing a typed node (addComment on a PR → "" → "pulls"): the type supplies the key.
//   - a name that maps to a MORE-PERMISSIVE-or-DIFFERENT resource than the node's type — the
//     IssueOrPullRequest-input mutations: unmarkIssueAsDuplicate ("issues") on a PullRequest node
//     ("pulls"), or createLinkedBranch ("branches") on an Issue node ("issues") — would otherwise ride
//     under the permitted key while the denied one (the node's true resource) is never checked (round-25).
//
// Requiring both is fail-closed (an extra scope can only deny) and is also the correct stricter behavior
// for createCommitOnBranch (name "contents" on a Ref node → "branches"): a commit that advances a branch
// tip legitimately needs BOTH contents and branches, preserving the round-15 contents="none" gate while
// no longer permitting it under branches="none". Reads keep the single name-guess (the response filter
// enforces per-resource on the redaction side).
func (h *Handler) nodeResourceKeys(access classifier.AccessLevel, typename, nameGuess string) []string {
	if access != classifier.Write {
		return []string{nameGuess}
	}
	keys := make([]string, 0, 2)
	if nameGuess != "" {
		keys = append(keys, nameGuess)
	}
	if h.GQLFilter != nil {
		if tr := h.GQLFilter.ResourceForType(typename); tr != "" && tr != nameGuess {
			keys = append(keys, tr)
		}
	}
	if len(keys) == 0 {
		return []string{""} // base access (e.g. a Repository node + a mutation name with no resource)
	}
	return keys
}

// resolveQuery is the static fallback used only when no schema is loaded (GQLFilter nil).
// In normal operation h.GQLFilter.NodeResolveQuery() covers every repo-scoped Node type.
const resolveQuery = `query($ids:[ID!]!){nodes(ids:$ids){__typename ` +
	`... on RepositoryNode{repository{nameWithOwner}} ` +
	`... on Repository{nameWithOwner} ` +
	`... on Ref{repository{nameWithOwner}} ` +
	`... on Release{repository{nameWithOwner}}}}`

func (h *Handler) resolveFromGitHub(ctx context.Context, ids []string) (map[string]nodeRes, error) {
	// Bound the resolve call: it returns a small fixed-shape response, so a slow/hung upstream
	// must not pin the client request indefinitely. Safe here (unlike the streaming forward path,
	// which carries arbitrarily large artifact downloads and gets no hard deadline).
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	query := resolveQuery
	if h.GQLFilter != nil {
		query = h.GQLFilter.NodeResolveQuery()
	}
	reqBody, _ := json.Marshal(map[string]any{
		"query":     query,
		"variables": map[string]any{"ids": ids},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.upstreamBase()+"/graphql", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+h.custodianToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "bgh-proxy/0.1")

	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Data struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}
	if parsed.Data.Nodes == nil {
		// No nodes array at all (e.g. a top-level error: rate limit, too complex). This is
		// a resolution failure, not per-node nulls → fail closed.
		return nil, fmt.Errorf("node resolution returned no nodes")
	}
	// GitHub's nodes(ids:) returns one entry per input ID, in order; the loop below maps by
	// position (ids[i]). A length mismatch means that positional assumption is broken — bail out
	// fail closed rather than risk attributing a node to the wrong ID (defense-in-depth).
	if len(parsed.Data.Nodes) != len(ids) {
		return nil, fmt.Errorf("node resolution returned %d nodes for %d ids", len(parsed.Data.Nodes), len(ids))
	}

	// GitHub returns nodes in input order; a null entry (invalid/unknown/no-access) decodes
	// to JSON null → skip (the upstream token can't resolve it, so it can't mutate it). A
	// non-null node carries __typename plus, for repo-scoped types, a uniquely-aliased
	// repository marker (the alias varies, so we scan every non-typename field for a
	// nameWithOwner). A node with __typename but no repository is non-repo — UNLESS its
	// type is repo-scoped per the schema (a repository we failed to read), which fails
	// closed so it can never slip through as "non-repo".
	out := make(map[string]nodeRes, len(ids))
	for i, raw := range parsed.Data.Nodes {
		if i >= len(ids) {
			break
		}
		id := ids[i]
		typename, nwo := parseResolvedNode(raw)
		if owner, repo, ok := splitNameWithOwner(nwo); ok {
			out[id] = nodeRes{kind: nodeRepo, owner: owner, repo: repo, typename: typename}
		} else if typename != "" && h.GQLFilter != nil && h.GQLFilter.IsRepoScopedType(typename) {
			// Repo-scoped type but no repository resolved → fail closed. IsRepoScopedType now also
			// covers union/interface-linked types like RepositoryRuleset (round-12 audit H5), so a
			// ruleset whose source is a Repository resolves to that repo and is policy-checked,
			// while an org-level one (no Repository source) yields no nameWithOwner and is denied.
			out[id] = nodeRes{kind: nodeDeny}
		} else if typename != "" && h.GQLFilter != nil && h.GQLFilter.IsRepoOwnedUnattributableNodeType(typename) {
			// A node whose runtime type BELONGS to a repository (by @docsCategory) but has NO field
			// path to that repository in the schema — Workflow (only argumented `runs`), DeployKey,
			// ClosedEvent (closable union with no Repository member), DeploymentReview, RepositoryTopic,
			// RepositoryCustomProperty, … These resolve to no nameWithOwner AND get no response marker,
			// so a node(id:)/nodes(ids:) reference to one would otherwise be treated as a constraint-
			// free non-repo node and stream the denied repo's data/identity/oracle unfiltered (round-16,
			// a surviving variant of the round-12 H1/H5 + round-15 drift-deny work — both coverage
			// invariants passed with it present). We cannot prove the repository, so fail closed.
			out[id] = nodeRes{kind: nodeDeny}
		} else if typename != "" && h.GQLFilter != nil && h.GQLFilter.IsRepoIdentityUnattributableType(typename) {
			// A known node type that exposes a repository identity (nameWithOwner) directly as a
			// scalar but resolved to no Repository object — the enterprise/migration namespace types
			// EnterpriseRepositoryInfo/UserNamespaceRepository/RepositoryMigration. The response
			// filter does not tag them (not repo-scoped), so treating them as constraint-free would
			// leak a denied repo's name/visibility under default=allow. Fail closed (round-18 H).
			out[id] = nodeRes{kind: nodeDeny}
		} else if typename != "" && h.GQLFilter != nil && h.GQLFilter.IsOwnerOwnedNodeType(typename) {
			// A known Node type owned by an ORG/USER/ENTERPRISE (Organization/Team/ProjectV2/audit
			// entries/…), not a repository. It is not repo-attributable, so neither the classifier scopes
			// it nor the repo-only response filter redacts it; under default=allow an empty-scope
			// node(id:) read of one would bypass an [[org]] deny (round-20, the owner-level analogue of the
			// round-16 repo-node fail-closed). Fail closed — the data is reachable via the SCOPED
			// organization(login:)/user(login:) root, which is policy-checked and filtered.
			out[id] = nodeRes{kind: nodeDeny}
		} else if typename != "" && h.GQLFilter != nil && !h.GQLFilter.IsKnownNodeObjectType(typename) {
			// A non-null node whose runtime __typename this embedded schema does NOT recognize as a
			// Node object type → live schema drift (GitHub's schema is ahead of the snapshot). The
			// resolve query is generated from the same snapshot, so it never asked for this type's
			// repository — a repo-scoped drift type would arrive unmarked and otherwise slip through
			// as "no constraint", letting a carrier multi-root mutation write into a denied repo.
			// Fail closed, mirroring how the request path denies untypeable queries (round-15).
			out[id] = nodeRes{kind: nodeDeny}
		} else {
			out[id] = nodeRes{kind: nodeSkip} // null node, or a recognized non-repo Node type → no constraint
		}
	}
	return out, nil
}

// parseResolvedNode extracts (__typename, nameWithOwner) from one resolved nodes(ids:)
// element. The repository marker is selected under a per-type alias, so it scans every
// field except __typename for either a "owner/repo" string (Repository.nameWithOwner) or
// an object {nameWithOwner:"owner/repo"} (other repo-scoped types). Returns "" typename
// for a JSON null node.
func parseResolvedNode(raw json.RawMessage) (typename, nwo string) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return "", "" // null or non-object → unresolved
	}
	_ = json.Unmarshal(fields["__typename"], &typename)
	for k, v := range fields {
		if k == "__typename" {
			continue
		}
		var val any
		if json.Unmarshal(v, &val) != nil {
			continue
		}
		// The resolve query's marker aliases hold only the path to nameWithOwner (e.g.
		// repository{nameWithOwner} or discussion{repository{nameWithOwner}}), so the one
		// "owner/repo" string anywhere within is this node's repository.
		if s := findNWO(val); s != "" {
			return typename, s
		}
	}
	return typename, ""
}

// findNWO returns the first "owner/repo" string anywhere within a resolved node's marker
// value, recursing through the nested objects the resolve path produces.
func findNWO(v any) string {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "/") {
			return t
		}
	case map[string]any:
		for _, c := range t {
			if s := findNWO(c); s != "" {
				return s
			}
		}
	case []any:
		for _, c := range t {
			if s := findNWO(c); s != "" {
				return s
			}
		}
	}
	return ""
}

func splitNameWithOwner(nwo string) (owner, repo string, ok bool) {
	if i := strings.IndexByte(nwo, '/'); i > 0 && i < len(nwo)-1 {
		return nwo[:i], nwo[i+1:], true
	}
	return "", "", false
}

func (h *Handler) upstreamBase() string {
	if h.UpstreamURL != "" {
		return h.UpstreamURL
	}
	return "https://api.github.com"
}

type policyContextKey struct{}

// EnforceRedirectPolicy is the upstream client's CheckRedirect. GitHub 301-redirects
// renamed/moved repos (preserving sub-paths), so a redirect to a SAME-HOST path is
// re-classified and re-evaluated against the request's policy — otherwise a request to an
// allowed path would be silently followed into a denied repo (the original classification
// only saw the requested path). Cross-host redirects (CDN downloads of already-authorized
// content; Go strips Authorization across hosts) are allowed. The client MUST be created
// with this as CheckRedirect; the proxy attaches the policy to the request context.
func EnforceRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	// Cross-host hop (e.g. codeload/objects CDN): the original request was already
	// policy-checked and Authorization is dropped across hosts, so this serves only the
	// authorized resource's content.
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		return nil
	}
	pol, _ := req.Context().Value(policyContextKey{}).(*policy.Policy)
	if pol == nil {
		return nil // internal call with no policy attached (node resolution never redirects)
	}
	c := classifier.Classify(req.Method, req.URL.Path, nil)
	// A same-host redirect must not change the response-FILTER shape the proxy already fixed for the
	// REQUESTED endpoint. respFilter/passScan are derived once in ServeHTTP from the original path and
	// reused for the final (post-redirect) body; re-checking authorization here is not enough. A
	// no-filter path-scoped read (e.g. GET /repos/o/r/contents/x → respFilter==nil) that upstream
	// redirects same-host to a cross-repo ENUMERATION endpoint (e.g. /user/repos, which the policy may
	// independently allow) would then stream that enumeration body UNREDACTED, leaking denied repos
	// (round-19 F1). The ONLY legitimate same-host redirect GitHub issues is a renamed/moved repo —
	// path-scoped to a single repository on both sides — so require both the origin and the target to
	// scope to one repo and refuse anything else. Cost is availability on exotic same-host redirects
	// (e.g. /repositories/{id}, which already fails closed off-spec), never a leak.
	if len(via) > 0 {
		orig := classifier.Classify(via[0].Method, via[0].URL.Path, nil)
		if !orig.HasRepo() || !c.HasRepo() {
			return fmt.Errorf("redirect target %q changes the response-filter scope (origin/target not single-repo); refusing", req.URL.Path)
		}
	}
	if res := evaluateScopes(pol, &c); !res.Allowed {
		return fmt.Errorf("redirect target %q denied by policy: %s", req.URL.Path, res.Reason)
	}
	return nil
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, start time.Time, normPath string, body []byte, pol *policy.Policy, tok *store.ProxyToken, classified *classifier.Result, respFilter func([]byte) ([]byte, bool), passScan func(string) bool) {
	base := h.upstreamBase()
	// Forward the path with the SAME percent-encoding the client sent (EscapedPath), not the
	// decoded normPath. Reassembling the decoded path into a URL string lets an encoded '?'
	// or '#' inside a segment re-split the URL: `/repos/o/r%3Fx/pulls` decodes to
	// `/repos/o/r?x/pulls`, which url.Parse then splits into path `/repos/o/r` + query
	// `x/pulls` — so GitHub serves repo `o/r` even though the classifier authorized `o/r?x`
	// (an org-allow + repo-deny policy would be bypassed). Keeping it escaped makes GitHub
	// route the exact (owner, repo) the classifier checked.
	upstream := base + classifier.NormalizePath(r.URL.EscapedPath())
	if normPath == "/graphql" || normPath == "/graphql/" {
		upstream = base + "/graphql"
	}

	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = io.NopCloser(byteReader(body))
	} else if r.Body != nil && body == nil {
		bodyReader = r.Body
	}

	// Carry the policy so the client's CheckRedirect (EnforceRedirectPolicy) can re-check
	// any same-host redirect target instead of blindly following it into another repo.
	ctx := context.WithValue(r.Context(), policyContextKey{}, pol)
	req, err := http.NewRequestWithContext(ctx, r.Method, upstream, bodyReader)
	if err != nil {
		slog.Error("creating upstream request", "err", err)
		jsonError(w, http.StatusBadGateway, "bgh: internal error")
		return
	}

	// Forward the client's headers so media-type negotiation (raw/diff/patch/SARIF,
	// tarball/zipball) and conditional requests (ETag/Last-Modified) keep working. The
	// client's Authorization is dropped and replaced with the real token; hop-by-hop
	// and length/host headers are not forwarded.
	for k, vals := range r.Header {
		if hopByHopOrManaged[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Authorization", "token "+h.custodianToken())
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "bgh-proxy/0.1")
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	tokenName := ""
	if tok != nil {
		tokenName = tok.Name
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		durationMs := time.Since(start).Milliseconds()
		errAuditAccess := "read"
		errAuditRepo := ""
		errAuditOrg := ""
		errAuditResource := ""
		errAuditUnscopedCategory := ""
		if classified != nil {
			errAuditAccess = classified.Access.String()
			errAuditRepo = classified.RepoFullName()
			errAuditOrg = classified.Org
			errAuditResource = classified.Resource
			errAuditUnscopedCategory = classified.UnscopedCategory
		}
		h.Audit.Log(audit.Entry{
			Timestamp:        time.Now(),
			Method:           r.Method,
			Path:             r.URL.Path,
			Repo:             errAuditRepo,
			Org:              errAuditOrg,
			Resource:         errAuditResource,
			UnscopedCategory: errAuditUnscopedCategory,
			Access:           errAuditAccess,
			PolicyResult:     "allowed",
			DurationMs:       durationMs,
			Mode:             h.Mode.String(),
			TokenName:        tokenName,
		})
		slog.Error("upstream request failed", "err", err)
		jsonError(w, http.StatusBadGateway, "bgh: upstream error")
		return
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	durationMs := time.Since(start).Milliseconds()

	auditAccess := "read"
	auditRepo := ""
	auditOrg := ""
	auditResource := ""
	auditUnscopedCategory := ""
	if classified != nil {
		auditAccess = classified.Access.String()
		auditRepo = classified.RepoFullName()
		auditOrg = classified.Org
		auditResource = classified.Resource
		auditUnscopedCategory = classified.UnscopedCategory
	}

	h.Audit.Log(audit.Entry{
		Timestamp:        time.Now(),
		Method:           r.Method,
		Path:             r.URL.Path,
		Repo:             auditRepo,
		Org:              auditOrg,
		Resource:         auditResource,
		UnscopedCategory: auditUnscopedCategory,
		Access:           auditAccess,
		PolicyResult:     "allowed",
		GitHubStatus:     &status,
		DurationMs:       durationMs,
		Mode:             h.Mode.String(),
		TokenName:        tokenName,
	})

	// Defense-in-depth for "Pass" REST responses (round-16): the static OpenAPI table believed this
	// non-path-scoped op is repo-free, but an under-typed response schema may hide a repo it never
	// located. Scan the actual JSON body for a denied repo and fail closed if present. Only JSON is
	// scanned — a binary download (Content-Type not JSON) streams untouched, so large archive/blob
	// reads are unaffected — and it never runs alongside respFilter (the cases are exclusive).
	if respFilter == nil && passScan != nil && isJSONContentType(resp.Header.Get("Content-Type")) {
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
		if rerr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if len(raw) > maxBodySize {
			slog.Warn("pass-response too large to scan; failing closed", "status", resp.StatusCode)
			jsonError(w, http.StatusBadGateway, "bgh: response too large to filter")
			return
		}
		scanOrg := classified.Org
		if scanOrg == "" {
			scanOrg = classified.Owner
		}
		denied, ok := restfilter.ContainsDeniedRepo(raw, scanOrg, passScan)
		if !ok {
			// JSON content-type but unparseable → anomalous for a repo-free op; fail closed.
			slog.Warn("pass-response JSON unparseable; failing closed", "status", resp.StatusCode)
			jsonError(w, http.StatusBadGateway, "bgh: response could not be filtered")
			return
		}
		if denied {
			slog.Warn("pass-response carries a repo the policy denies but the OpenAPI table did not locate; failing closed", "status", resp.StatusCode)
			jsonError(w, http.StatusForbidden, "bgh: denied")
			return
		}
		copyResponseHeaders(w.Header(), resp.Header, true)
		w.WriteHeader(resp.StatusCode)
		w.Write(raw)
		return
	}

	// When a response filter is set (GraphQL reads), buffer the body, redact denied
	// repos, and send the filtered bytes; the Content-Length will be recomputed.
	if respFilter != nil {
		// Read one byte past the cap to DETECT truncation. A response filtered by restfilter
		// fails OPEN on an unparseable body (its defense-in-depth pass-through), so a body
		// silently truncated at maxBodySize would be re-emitted with denied-repo entries intact
		// (round-12 audit M3). Fail closed on overflow instead, like the request path does.
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
		if rerr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if len(raw) > maxBodySize {
			slog.Warn("filtered response exceeds size cap; denying rather than forwarding a truncated (unredactable) body", "status", resp.StatusCode)
			jsonError(w, http.StatusBadGateway, "bgh: response too large to filter")
			return
		}
		filtered, ok := respFilter(raw)
		if !ok {
			// The body could not be parsed/redacted; fail closed rather than forward
			// bytes we could not filter. After Accept-Encoding is dropped upstream this
			// is only reachable for a genuinely non-JSON /graphql body.
			slog.Warn("graphql response not filterable; denying", "status", resp.StatusCode)
			jsonError(w, http.StatusBadGateway, "bgh: response could not be filtered")
			return
		}
		copyResponseHeaders(w.Header(), resp.Header, true)
		w.WriteHeader(resp.StatusCode)
		w.Write(filtered)
		return
	}

	copyResponseHeaders(w.Header(), resp.Header, false)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// strippedResponseHeaders are upstream response headers never forwarded to the client.
// Transfer-Encoding/Content-Encoding are managed by our transport (bodies arrive decoded);
// the X-OAuth-* headers reveal the custodian token's scopes and OAuth client id, which a
// proxy-token holder must not learn (the proxy exists to hide that token's reach). X-GitHub-SSO
// (canonicalized to "X-Github-Sso") reveals the SAML-SSO organization IDs the custodian token is
// authorized for — the same custodian-reach class as X-OAuth-* — so it is stripped too. Set-Cookie
// is never relayed: the proxy is not a cookie-session service and must not forward upstream cookies.
// This is a denylist, not an allowlist: keeping the broad set of benign GitHub headers (ETag, Link,
// X-RateLimit-*, X-GitHub-Request-Id, Retry-After, …) that clients depend on, at the cost of
// requiring any new custodian-revealing header GitHub introduces to be added here.
var strippedResponseHeaders = map[string]bool{
	"Transfer-Encoding":       true,
	"Content-Encoding":        true,
	"X-Oauth-Scopes":          true,
	"X-Accepted-Oauth-Scopes": true,
	"X-Oauth-Client-Id":       true,
	"X-Github-Sso":            true,
	"Set-Cookie":              true,
	// Github-Authentication-Token-Expiration discloses the CUSTODIAN token's expiry timestamp (and,
	// by its presence, that the custodian is an expiring OAuth/user-to-server or fine-grained token —
	// exactly what loginflow mints). The value isn't the token, but a property of the custodian's
	// reach/lifecycle, the same disclosure class as X-OAuth-Scopes/X-Github-Sso — so strip it (round-20).
	"Github-Authentication-Token-Expiration": true,
}

func copyResponseHeaders(dst, src http.Header, stripContentLength bool) {
	for key, vals := range src {
		if strippedResponseHeaders[key] || (stripContentLength && key == "Content-Length") {
			continue
		}
		for _, v := range vals {
			dst.Add(key, v)
		}
	}
}

// isJSONContentType reports whether a response Content-Type is JSON (application/json or a +json
// vendor type), so the Pass-response defense-in-depth scan applies only to JSON bodies and leaves
// binary downloads (archives, raw blobs, diffs) to stream untouched.
func isJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

type byteReaderWrapper struct {
	data []byte
	pos  int
}

func byteReader(b []byte) *byteReaderWrapper {
	return &byteReaderWrapper{data: b}
}

func (r *byteReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
