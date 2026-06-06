package gqlfilter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
)

// markerAlias is the response field injected into every repo-scoped object so it
// self-identifies its repository. A "__" prefix is reserved by GraphQL, so this uses a
// plain (collision-unlikely) alias.
const markerAlias = "bghRepoTagZ9"

// markerTypeAlias is injected alongside markerAlias as `bghRepoTypeZ9: __typename`, so the
// filter learns each repo-scoped object's RUNTIME type and can map it to a per-resource key
// (PullRequest→"pulls", Issue→"issues", …). This makes per-resource policy enforceable no
// matter how an object is reached — including navigating back to the same repo — which the
// repo-only marker cannot do (it is repo-granular). Stripped from the response like markerAlias.
const markerTypeAlias = "bghRepoTypeZ9"

// ownerMarkerAlias is injected as `bghOrgLoginZ9: login` (Organization) / `: slug` (Enterprise) onto every
// owner object so the response filter can enforce org/enterprise policy on owner-private data reached by
// ANY navigation path, not just an org/user/enterprise ROOT (round-25/26). Reserved so a client cannot
// pre-declare it to forge/suppress redaction.
const ownerMarkerAlias = "bghOrgLoginZ9"

// ownerMemberMarkerPrefix + the member field's RESPONSE KEY is injected as a sibling marker for each
// member-identity field selected on an owner object, so RedactDeniedOwnerPrivate can null that field by
// its real key regardless of a client ALIAS (round-26: a `roster: membersWithRole` alias defeated the
// round-25 null-by-field-name). The suffix is the response key, which is a valid GraphQL name.
const ownerMemberMarkerPrefix = "bghOrgMemZ9_"

// userGistMarkerPrefix marks a navigated User's GIST-category private field (gists/gist/gistComments) so the
// response filter gates it on the "gists" policy category rather than "user_private". The marker prefix —
// not the response key — carries the category, because the key is the client ALIAS (a `mine: gists` alias),
// and deriving the category from the alias (UserGistField is keyed by field NAME) downgraded gists→user_private
// and leaked the custodian's SECRET gists past a gists-denied grant (round-36). Non-gist private User fields
// keep ownerMemberMarkerPrefix (category "user_private"). The suffix is the response key (for nulling).
const userGistMarkerPrefix = "bghUGstZ9_"

// userOwnContentMarkerPrefix marks a navigated User's private field that returns the user's OWN owner-owned
// CONTENT (projectsV2/sponsorsListing/…, the userOwnContentFields), as opposed to a private field that
// returns a FOREIGN entity (sponsoring/sponsors/organizations → other Users/Orgs). Only an own-content field
// may carry the userOwnedAmbient sentinel into its subtree — an entity-returning private field must NOT, or
// the sentinel rides through the foreign entity to a cross-owner self-marked node and keeps it (round-44
// Finding 1). The category is still "user_private" (the field is nulled when user_private is denied); the
// distinct prefix only tells redaction whether to thread the sentinel. The suffix is the response key.
const userOwnContentMarkerPrefix = "bghUOCZ9_"

// orgMemberFieldNames are Organization member-identity fields (synced with the classifier's
// gqlOrgFieldToResource "members" keys); enterpriseMemberFieldNames are the Enterprise counterparts.
// A member field is nulled when the owner's "members" carve-out is denied but base IS readable.
var orgMemberFieldNames = map[string]bool{
	"membersWithRole": true, "members": true, "pendingMembers": true, "memberStatuses": true,
	"mannequins": true, "enterpriseOwners": true, "samlIdentityProvider": true, "auditLog": true,
}
var enterpriseMemberFieldNames = map[string]bool{
	"members": true, "administrators": true, "ownerInfo": true, "memberInvitations": true,
}

// ownerContentMarkerPrefix marks a navigated Organization/Enterprise's owner-private CONTENT field with the
// per-resource policy key that gates it, so RedactDeniedOwnerPrivate nulls it when that resource is denied —
// the response-side enforcement the round-37/38 REQUEST-side mapping lacked, which navigation (Team.organization,
// User.organization, deep repository().owner, EnterpriseOwnerInfo) bypassed (round-39). The marker alias is
// `ownerContentMarkerPrefix + resourceCode + "__" + responseKey`: resourceCode (the resource with '-'→'X',
// alias-safe) carries the resource alias-immune (round-36 lesson), the response KEY (after the FIRST "__")
// addresses the field to null alias-proof (round-26 lesson). This is the member-field mechanism generalized
// from one hardcoded "members" resource to every owner-private content resource.
const ownerContentMarkerPrefix = "bghOwnerCZ9_"

// ownerSelfMarkerPrefix marks an owner-OWNED content TYPE (ProjectV2 @docsCategory "projects", classic Project,
// a Sponsorship/SponsorsTier, …) reached by NAVIGATION (issue.projectItems.project — not via node(id:) which
// already fails closed, nor via the content-marked organization(){projectsV2} field). The marker carries the
// resource (in the prefix suffix, alias-safe); RedactDeniedOwnerPrivate nulls the object's content when there
// is NO marked owner ancestor to attribute it to (fail closed) or that ambient owner's resource is denied —
// the owner analogue of the repoOwnedNoPath ambient attribution (round-41).
const ownerSelfMarkerPrefix = "bghOwnerSZ9_"

// userOwnedAmbient is the ambientOwner value threaded through a navigated User's subtree, so an owner-owned
// content type reached UNDER a User (viewer/user(login:){projectsV2} → the custodian's own projects, gated on
// the user_private category by the User field markers, NOT the org "projects" resource) is NOT fail-closed by
// the ownerSelfMarker. It is an internal sentinel (never a real owner login), distinct from "" (no owner
// ancestor → fail closed) and from a real org/enterprise login (round-41).
const userOwnedAmbient = "\x00user"

// ownerContentResource maps an owner-private CONTENT field (NOT a member/team roster field — those keep the
// ownerMemberMarkerPrefix mechanism) to its per-resource policy key, mirroring the classifier's
// gqlOrgFieldToResource + gqlEnterpriseFieldToResource. TestR39_OwnerContentResourceInSync couples it to the
// classifier so the request and response sides cannot drift.
//
// viewerPrivateContentResource is a SENTINEL "resource" (alias-safe, matches no real per-resource key) for an
// owner field that is actually the VIEWER's (custodian's) private data, not the owner's — the Sponsorable
// `sponsorshipForViewerAs*` fields, which return the custodian's own sponsorship tier price / payment source /
// privacy level relative to the navigated org/user (round-40 F3/F4/F8). RedactDeniedOwnerPrivate gates a marker
// carrying this sentinel on the user_private CATEGORY (categoryDenied), not the owner's per-resource policy, so
// it is denied to any token lacking user_private regardless of the owner grant.
const viewerPrivateContentResource = "viewerprivateZZ"

var ownerContentResource = map[string]string{
	// viewer-private-on-owner (gated on the user_private category via the sentinel): the custodian's own
	// sponsorship financials AND the existence bits revealing whether the custodian sponsors / is sponsored
	// by this navigated account (round-40 sponsorshipForViewerAs*; round-41 the viewer* booleans).
	"sponsorshipForViewerAsSponsor": viewerPrivateContentResource, "sponsorshipForViewerAsSponsorable": viewerPrivateContentResource,
	"viewerIsSponsoring": viewerPrivateContentResource, "isSponsoringViewer": viewerPrivateContentResource,
	"viewerCanSponsor": viewerPrivateContentResource,
	// the org/enterprise PRIVATE team inventory (names/slugs/privacy) — a teams="none" carve-out the REST
	// GET /orgs/{org}/teams and the organization(){teams} root both gate was bypassed response-side on a
	// navigation path (round-41 finding-5).
	"team": "teams", "teams": "teams", "enterpriseTeam": "teams", "enterpriseTeams": "teams",
	// Organization
	"projectsV2": "projects", "projectV2": "projects", "projects": "projects",
	"project": "projects", "recentProjects": "projects",
	"sponsorsActivities": "sponsors", "monthlyEstimatedSponsorsIncomeInCents": "sponsors",
	"estimatedNextSponsorsPayoutInCents": "sponsors", "totalSponsorshipAmountAsSponsorInCents": "sponsors",
	"lifetimeReceivedSponsorshipValues": "sponsors", "sponsorshipsAsMaintainer": "sponsors",
	"sponsorshipsAsSponsor": "sponsors", "sponsorshipNewsletters": "sponsors",
	"sponsors": "sponsors", "sponsoring": "sponsors",
	"rulesets": "rulesets", "ruleset": "rulesets",
	"repositoryCustomProperties": "properties", "repositoryCustomProperty": "properties",
	"interactionAbility": "interaction-limits",
	"domains":            "settings", "ipAllowListEntries": "settings",
	"ipAllowListEnabledSetting": "settings", "ipAllowListForInstalledAppsEnabledSetting": "settings",
	"announcementBanner": "settings", "organizationBillingEmail": "settings",
	"notificationDeliveryRestrictionEnabledSetting": "settings",
	"packages":    "packages",
	"issueTypes":  "issue-types",
	"issueFields": "issue-fields",
	// Enterprise (member/team fields ownerInfo/members/enterpriseTeam(s) keep the member mechanism)
	"billingInfo": "billing", "billingEmail": "billing",
	"securityContactEmail": "settings", "readme": "settings", "readmeHTML": "settings",
	"organizations":             "organizations",
	"userNamespaceRepositories": "members",
}

// resourceCode encodes a per-resource key into an alias-safe marker token ('-'→'X'; no resource key contains
// 'X' or '_'); resourceFromCode reverses it.
func resourceCode(resource string) string { return strings.ReplaceAll(resource, "-", "X") }
func resourceFromCode(code string) string { return strings.ReplaceAll(code, "X", "-") }

// contentBearingNonOwnerResource returns the per-resource key for an owner-private CONTENT field on a NON-owner
// type that carries its enclosing owner's data (EnterpriseOwnerInfo's org-inventory / roster connections,
// reached one hop below enterprise(slug:) via ownerInfo) — nulled under the ambient owner's carve-out, the
// content analogue of memberBearingNonOwnerTypes (round-39 finding-5). The *SettingOrganizations suffix rule
// auto-covers any future enterprise org-inventory field.
func contentBearingNonOwnerResource(typeName, field string) string {
	switch typeName {
	case "EnterpriseOwnerInfo":
		// EnterpriseOwnerInfo is the enterprise's ADMIN/SETTINGS object — only an enterprise owner sees it — so
		// EVERY field is owner-private content: the member-org INVENTORY partitioned by setting
		// (*SettingOrganizations → organizations), the admin/collaborator rosters + pending invitations →
		// members, and everything else (verified domains, IP-allow-list, SAML config, 2FA enforcement, …) →
		// settings (round-39 inventory; round-40 settings-class). The suffix rule auto-covers future
		// *SettingOrganizations fields.
		switch {
		case strings.HasSuffix(field, "SettingOrganizations"):
			return "organizations"
		case field == "admins" || field == "outsideCollaborators" || field == "affiliatedUsersWithTwoFactorDisabled" ||
			strings.HasPrefix(field, "pending") && strings.Contains(field, "nvitation"):
			return "members"
		case field == "id" || field == "__typename":
			return ""
		default:
			return "settings"
		}
	case "Team":
		// Team carries its owning ORG's CONTENT one hop below organization(){teams{nodes{…}}} — its project
		// boards (projectsV2/projects/…). Member fields keep the round-26 member-marker mechanism (round-40).
		if r, ok := ownerContentResource[field]; ok {
			return r
		}
	case "EnterpriseUserAccount":
		// An enterprise member account exposes the enterprise's per-member org-membership INVENTORY (round-40).
		if field == "organizations" {
			return "organizations"
		}
	}
	return ""
}

// contentBearingNonOwnerTypes are the NON-owner types whose own augment branch must inject content markers
// (Team is handled in the memberBearingNonOwnerTypes branch). TestR40_ContentBearingNonOwnerCovered derives
// the complete set from the schema so a refresh that adds another such type fails the build.
var contentBearingNonOwnerTypes = map[string]bool{
	"EnterpriseOwnerInfo": true, "EnterpriseUserAccount": true,
}

// OwnerContentResource exposes the field→resource map so a cross-package guard can couple it to the classifier.
func OwnerContentResource() map[string]string {
	out := make(map[string]string, len(ownerContentResource))
	for k, v := range ownerContentResource {
		out[k] = v
	}
	return out
}

// userMarkerAlias marks a User reached as an interface/union possible type (Sponsorable/ProfileOwner/…)
// when an owner-PRIVATE User field is selected, so RedactDeniedOwnerPrivate can null those fields for a
// DENIED user. A User is NOT coarse-redacted like an Organization (it is reached everywhere as an
// Actor/author, so coarse would null every user's data under default-deny) — only its curated private
// fields are nulled, by the per-field response-key markers, and only when a private field is selected.
const userMarkerAlias = "bghOwnerUserZ9"

// userPrivateFields are User fields that are owner-private — the custodian's (or any user's) account data
// that GitHub returns ONLY to that user themselves: the navigated User resolves to the custodian via an
// author/owner/uploadedBy/collaborators.node/...on User edge (the viewer IS the custodian), so without
// response-side nulling these stream to a token that holds only an ordinary repo grant — bypassing the
// classifier's viewer/user(login:)/repositoryOwner(login:) front gate, which never sees a NAVIGATED User
// (round-35). On a denied User they are nulled PRECISELY (per-field markers), NOT coarse-redacted like an
// Organization — a User is reached everywhere as a plain Actor/author{login}, so coarse nulling would
// break every author. A User is marked (and these fields injected) ONLY when one of these is selected, so
// author{login} stays unmarked. The set is build-time coupled to the classifier's viewerPrivateFieldCategory
// (the front-gate private set) by TestR35_UserPrivateFieldSetsCoupled so the two cannot drift.
var userPrivateFields = map[string]bool{
	// Sponsors financials + org-verified domain emails (also Sponsorable common fields, round-28/30).
	"monthlyEstimatedSponsorsIncomeInCents": true, "estimatedNextSponsorsPayoutInCents": true,
	"totalSponsorshipAmountAsSponsorInCents": true, "lifetimeReceivedSponsorshipValues": true,
	"sponsorsActivities": true, "organizationVerifiedDomainEmails": true,
	// incoming/outgoing sponsorship CONNECTIONS (include PRIVATE sponsorships: sponsor identity, tier
	// price, paymentSource, newsletters) — owner-private to the account (round-30).
	"sponsorshipsAsMaintainer": true, "sponsorshipsAsSponsor": true, "sponsorshipNewsletters": true,
	"sponsors": true, "sponsoring": true,
	// sponsorsListing is the account's Sponsors LISTING — public for a third-person view, but for the
	// OWNER's own listing (viewer==owner, e.g. repository(owner:"<custodian>").owner→...on User) it exposes
	// activeStripeConnectAccount{accountId,stripeDashboardUrl}, contactEmailAddress and billingCountryOrRegion.
	// The classifier already gates it user_private at the viewer/user root (viewerPrivateFieldCategory); a
	// navigated owner edge bypassed that, leaking the custodian's payment data under a metadata-only grant.
	// Same realization the round-40 sponsorshipForViewerAs* move made; remove from r35ViewerRelativePublic
	// (round-42 F1).
	"sponsorsListing": true,
	// The custodian's private account collections/scalars (round-35) — the response-side parity of the
	// classifier's viewer/user(login:) un-flooring. Reached via author/uploadedBy/owner/...on User edges.
	"email": true, "gists": true, "gist": true, "gistComments": true, "savedReplies": true,
	"organizations": true, "organization": true, "enterprises": true, "publicKeys": true,
	"gpgKeys": true, "sshSigningKeys": true, "socialAccounts": true, "projectsV2": true,
	"projectV2": true, "projects": true, "project": true, "recentProjects": true,
	"interactionAbility": true,
	// pinnableItems/pinnedItems/itemShowcase surface the custodian's SECRET gists via the PinnableItem
	// (Gist|Repository) union — gated on "gists" so a navigated author's pinned secret gists are nulled
	// when the gists category is denied (round-36).
	"pinnableItems": true, "pinnedItems": true, "itemShowcase": true,
	// sponsorshipForViewerAs* return the CUSTODIAN's own (viewer-relative) private sponsorship — tier price,
	// payment source, privacy level — relative to this navigated user; viewerIsSponsoring/isSponsoringViewer/
	// viewerCanSponsor are the existence bits. Gated on user_private so a navigated User edge cannot leak the
	// custodian's sponsorship relationships (round-40 F3/F4/F8 + round-41 F2, correcting r35ViewerRelativePublic).
	"sponsorshipForViewerAsSponsor": true, "sponsorshipForViewerAsSponsorable": true,
	"viewerIsSponsoring": true, "isSponsoringViewer": true, "viewerCanSponsor": true,
}

// userGistFields are the userPrivateFields whose policy category is "gists" (parity with REST /gists and
// node(id:Gist)) rather than "user_private", so the response-side redaction gates them on the gists grant.
var userGistFields = map[string]bool{
	"gists": true, "gist": true, "gistComments": true,
	"pinnableItems": true, "pinnedItems": true, "itemShowcase": true,
}

// userOwnContentFields are the userPrivateFields whose DIRECT value is the user's OWN owner-owned CONTENT
// (a self-marked ProjectV2/Project/SponsorsListing). ONLY these may carry the userOwnedAmbient sentinel into
// their subtree (so the user's own projects/listing are kept, not fail-closed). Every OTHER private field —
// sponsoring/sponsors (→ foreign Sponsorable Users/Orgs), organizations/enterprises (→ Orgs), the
// sponsorshipsAs* connections (→ Sponsorships referencing a FOREIGN sponsorable's tier/listing) — must NOT
// carry the sentinel: it would ride through the foreign entity to a cross-owner self-marked node and keep it
// (round-44 Finding 1). TestR44_UserOwnContentFieldsAreSelfMarked couples this set to the schema so a field
// whose type is not owner-owned content cannot be added here. The over-redaction of a user's own deep
// content (a sponsorship's tier, a project's items) reached through a non-own-content private field is the
// safe direction.
// (classic `projects`/`project` are deliberately ABSENT: their type Project is repo-attributable, handled by
// the repo filter — not the owner self-marker — so they need no sentinel; TestR44_UserOwnContentFieldsCoupled
// enforces that every member resolves to a self-marked owner-owned content type.)
// `recentProjects` is ALSO deliberately ABSENT (round-45 F2): although it returns a self-marked ProjectV2, the
// schema documents it as "projects this user has recently modified IN THE CONTEXT OF THE OWNER" — i.e. it can
// be a FOREIGN org's board, not the user's own, so the user-owned sentinel would keep it past that org's
// `projects="none"`. The coupling guard cannot see cross-owner-ness (it is in the field's prose), so a field
// added here MUST be own-only by inspection; `recentProjects` fails closed (the user reads its own boards via
// `projectsV2`).
var userOwnContentFields = map[string]bool{
	"projectsV2": true, "projectV2": true, "sponsorsListing": true,
}

// UserPrivateFields returns the owner-private User field names (sorted), so a cross-package guard can
// couple them to the classifier's viewer-private front-gate set. UserGistField reports whether a
// private User field is gated on the "gists" category rather than "user_private".
func UserPrivateFields() []string {
	out := make([]string, 0, len(userPrivateFields))
	for f := range userPrivateFields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// UserGistField reports whether an owner-private User field is gated on the "gists" policy category.
func UserGistField(field string) bool { return userGistFields[field] }

// userPrivateMarkerPrefix returns the response-side marker prefix that encodes a navigated User-private
// field's policy CATEGORY by its schema field NAME (not the client alias): gist-category fields get
// userGistMarkerPrefix ("gists"), all others ownerMemberMarkerPrefix ("user_private"). The category must be
// fixed here, at augment time, because at redaction time only the marker survives and its suffix is the
// client ALIAS — deriving the category from that alias downgraded gists→user_private (round-36).
func userPrivateMarkerPrefix(fieldName string) string {
	if userGistFields[fieldName] {
		return userGistMarkerPrefix
	}
	if userOwnContentFields[fieldName] {
		return userOwnContentMarkerPrefix
	}
	return ownerMemberMarkerPrefix
}

// memberBearingNonOwnerTypes are object types that are NOT themselves an owner (Organization/Enterprise)
// but expose their owning org's/enterprise's member identity — Team (members/memberStatuses/invitations),
// reachable by navigation (organization(){teams{nodes{members}}}). They have no owner-id scalar, so the
// filter attributes them to the nearest marked owner ANCESTOR and redacts them under that owner's "members"
// carve-out (the owner analogue of repoOwnedNoPath ambient attribution). TestOwnerPrivateCoverage asserts
// this set ∪ {Organization, Enterprise} ∪ the justified exceptions covers every member-bearing type.
var memberBearingNonOwnerTypes = map[string]map[string]bool{
	"Team":           {"members": true, "memberStatuses": true, "invitations": true},
	"EnterpriseTeam": {"enterpriseTeamMembers": true, "assignedOrganizations": true},
}

// ownerPublicFields are the only fields kept when an owner object is BASE-denied (the client has no
// org/enterprise access at all); every other field — billing, IP allow-list, domains, 2FA, members, … —
// is nulled. Keeping by exact key (an aliased public field is also nulled) is safe here precisely BECAUSE
// base is denied: over-redaction costs availability, never a leak. This is drift-proof: it does not
// enumerate the (large, GitHub-evolving) owner-private field set, it nulls everything NOT public.
var ownerPublicFields = map[string]bool{
	"login": true, "name": true, "id": true, "__typename": true, "slug": true,
	"url": true, "avatarUrl": true, "databaseId": true, "resourcePath": true,
}

// OrgMemberFieldNames returns the Organization member-identity field names; a classifier test asserts it
// equals the gqlOrgFieldToResource "members" keys so the request and response sides cannot drift.
func OrgMemberFieldNames() []string {
	out := make([]string, 0, len(orgMemberFieldNames))
	for f := range orgMemberFieldNames {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// RedactDeniedOwnerPrivate enforces org/enterprise policy on owner-private GraphQL data reached by ANY
// navigation path — the response-side backstop the repo-centric marker filter and the org-ROOT-only
// classifier scope both miss. For every owner object the augmenter marked (Organization/Enterprise):
//   - if the owner is BASE-denied (no access), keep only public-identity fields and null the rest
//     (billing/IP-allow-list/domains/2FA/members/…) — drift-proof and alias-proof;
//   - else if its "members" carve-out is denied, null exactly the member-identity fields, addressed by
//     the per-field RESPONSE-KEY markers so a client ALIAS cannot evade the null (round-26).
//
// `denied(owner, resource)` reports whether the policy denies that owner's resource ("" = base). The owner
// marker and all member markers are always stripped, denied or not.
//
// `categoryDenied(category)` reports whether the policy denies a navigated User's owner-private field by its
// POLICY CATEGORY ("gists" for gist fields, "user_private" otherwise) — independent of the user's login, so a
// token that merely holds an `[[org]] name="<login>"` repo-enumeration grant (which would satisfy the
// org-login `denied` gate) still cannot read the resolved user's private email/gists/keys via navigation,
// matching the classifier's viewer/user(login:) front gate (round-35). The category is carried by the marker
// PREFIX (set from the schema field name at augment time), not the aliasable response key (round-36).
func RedactDeniedOwnerPrivate(v any, denied func(owner, resource string) bool, categoryDenied func(category string) bool) any {
	return redactOwnerPrivate(v, denied, categoryDenied, "")
}

// redactOwnerPrivate threads the ambientOwner — the login/slug of the nearest enclosing marked
// Organization/Enterprise — so a member-bearing NON-owner object (Team) reached by navigation is attributed
// to its owner and redacted under that owner's "members" carve-out (round-26 structural). An owner object
// supplies its own owner (and becomes the ambient for its subtree); a member-bearing object with NO
// attributable owner fails closed (its member fields are nulled).
func redactOwnerPrivate(v any, denied func(owner, resource string) bool, categoryDenied func(category string) bool, ambientOwner string) any {
	switch val := v.(type) {
	case map[string]any:
		// owner-OWNED content TYPE reached by navigation (ProjectV2 etc., bghOwnerSZ9_<resource>): fail closed —
		// null its content when there is NO marked owner ancestor to attribute it to (e.g. reached under a repo,
		// the round-41 finding-1 issue.projectItems.project leak) or that ambient owner's resource is denied.
		selfMarkedUserOwned := false
		for k := range val {
			if code, ok := strings.CutPrefix(k, ownerSelfMarkerPrefix); ok {
				delete(val, k)
				res := resourceFromCode(code)
				if ambientOwner == userOwnedAmbient {
					// userOwnedAmbient → this is the user's OWN owner-owned content (its projectsV2/sponsorsListing
					// reached DIRECTLY through a userPrivateField the User markers already gate on user_private) —
					// KEEP it. But the sentinel is NON-TRANSITIVE (round-43 F1/F2): it must NOT reach this node's
					// children, because a NESTED self-marked owner-owned object is a SEPARATE owner's content (a
					// cross-owner ProjectV2 via issue.projectItems.project, the sponsorable's tier.sponsorsListing)
					// that must fail closed on its own. The reset to "" happens at the generic recursion below.
					selfMarkedUserOwned = true
				} else if ambientOwner == "" || denied(ambientOwner, res) {
					// No marked owner ancestor (reached under a repo) or that owner's resource is denied → fail
					// closed. Null EVERY non-marker field by RESPONSE KEY: a former {__typename,id} keep-set was
					// alias-bypassable (a client `id: <secret-scalar>` aliased the secret to a kept key and
					// dodged the null), so keep NOTHING — the object's structural presence is unavoidable but
					// carries no data (round-43 F3; the keep-by-key was the round-42 F5 mechanism's residual).
					for fk := range val {
						if !strings.HasPrefix(fk, "bgh") {
							val[fk] = nil
						}
					}
				}
				break
			}
		}
		// A User is marked ONLY for its own owner-private fields and is NEVER coarse-redacted: null exactly
		// the per-field-marked private fields when THIS user is base-denied OR the field's policy category
		// (user_private/gists) is denied, keeping all its public data (round-28; category gate round-35).
		if userLogin, ok := val[userMarkerAlias].(string); ok {
			delete(val, userMarkerAlias)
			// Each per-field marker carries the field's policy CATEGORY in its PREFIX (set at augment time
			// from the schema field NAME), so a client ALIAS on the field cannot downgrade gists→user_private
			// (round-36). The suffix is the response key, used to null the field.
			type marked struct {
				key, cat   string
				ownContent bool // field returns the user's OWN owner-owned content → may carry the sentinel
			}
			var ms []marked
			for k := range val {
				if rest, isGist := strings.CutPrefix(k, userGistMarkerPrefix); isGist {
					ms = append(ms, marked{rest, "gists", false})
				} else if rest, ok := strings.CutPrefix(k, userOwnContentMarkerPrefix); ok {
					ms = append(ms, marked{rest, "user_private", true})
				} else if rest, ok := strings.CutPrefix(k, ownerMemberMarkerPrefix); ok {
					ms = append(ms, marked{rest, "user_private", false})
				}
			}
			ownContentKeys := make(map[string]bool, len(ms))
			for _, m := range ms {
				switch {
				case m.cat == "gists":
					delete(val, userGistMarkerPrefix+m.key)
				case m.ownContent:
					delete(val, userOwnContentMarkerPrefix+m.key)
					ownContentKeys[m.key] = true
				default:
					delete(val, ownerMemberMarkerPrefix+m.key)
				}
				if denied(userLogin, "") || categoryDenied(m.cat) {
					if _, present := val[m.key]; present {
						val[m.key] = nil
					}
				}
			}
			for k, c := range val {
				// The user-owned sentinel suppresses the ownerSelfMarker fail-close ONLY for the user's OWN
				// owner-owned content reached through an OWN-CONTENT private field (projectsV2/sponsorsListing).
				// It is NOT threaded into an ENTITY-returning private field (sponsoring/sponsors/organizations →
				// foreign Users/Orgs) nor any non-private field: that would let the sentinel ride through the
				// foreign entity to a CROSS-OWNER self-marked node and keep it past a per-resource carve-out
				// (round-44 Finding 1). The round-43 non-transitive reset then zeroes the sentinel below the
				// first self-marked own node, so even an own-content field cannot leak its deep references.
				child := ambientOwner
				if ownContentKeys[k] {
					child = userOwnedAmbient
				}
				val[k] = redactOwnerPrivate(c, denied, categoryDenied, child)
			}
			return val
		}
		effectiveOwner := ambientOwner
		isOwnerObj := false
		if o, ok := val[ownerMarkerAlias].(string); ok {
			effectiveOwner = o
			isOwnerObj = true
			delete(val, ownerMarkerAlias)
		}
		var memberKeys []string
		for k := range val {
			if strings.HasPrefix(k, ownerMemberMarkerPrefix) {
				memberKeys = append(memberKeys, strings.TrimPrefix(k, ownerMemberMarkerPrefix))
			}
		}
		for _, key := range memberKeys {
			delete(val, ownerMemberMarkerPrefix+key)
		}
		// CONTENT markers (round-39): `ownerContentMarkerPrefix + resourceCode + "__" + responseKey` — the
		// resource is carried by the code (alias-immune), the response key (after the FIRST "__") addresses
		// the field. Null each content field when its per-resource key is denied for this owner.
		type contentMark struct{ resource, key string }
		var contentMarks []contentMark
		for k := range val {
			if rest, ok := strings.CutPrefix(k, ownerContentMarkerPrefix); ok {
				if code, key, found := strings.Cut(rest, "__"); found {
					contentMarks = append(contentMarks, contentMark{resourceFromCode(code), key})
				}
			}
		}
		for _, cm := range contentMarks {
			delete(val, ownerContentMarkerPrefix+resourceCode(cm.resource)+"__"+cm.key)
		}
		switch {
		case isOwnerObj && denied(effectiveOwner, ""):
			// base-denied owner → keep only public identity, null everything else (drift-proof; covers all
			// member + content fields).
			for k := range val {
				if !ownerPublicFields[k] {
					val[k] = nil
				}
			}
		default:
			// base-allowed owner (or member/content-bearing non-owner attributed to its ambient owner): null
			// each marked field whose per-resource key is denied (members for member markers, the marker's
			// resource for content markers). A field with no attributable owner (effectiveOwner=="") fails closed.
			if len(memberKeys) > 0 && (effectiveOwner == "" || denied(effectiveOwner, "members")) {
				for _, key := range memberKeys {
					if _, present := val[key]; present {
						val[key] = nil
					}
				}
			}
			for _, cm := range contentMarks {
				var deny bool
				if cm.resource == viewerPrivateContentResource {
					deny = categoryDenied("user_private") // the custodian's own data, gated on the category
				} else {
					deny = effectiveOwner == "" || denied(effectiveOwner, cm.resource)
				}
				if deny {
					if _, present := val[cm.key]; present {
						val[cm.key] = nil
					}
				}
			}
		}
		nextAmbient := ambientOwner
		if isOwnerObj {
			nextAmbient = effectiveOwner
		} else if selfMarkedUserOwned {
			// non-transitive user-owned sentinel: the keep applied to THIS node only; its children start fresh
			// with no owner ancestor, so a nested self-marked owner-owned object fails closed (round-43 F1/F2).
			nextAmbient = ""
		}
		for k, c := range val {
			val[k] = redactOwnerPrivate(c, denied, categoryDenied, nextAmbient)
		}
		return val
	case []any:
		for i, c := range val {
			val[i] = redactOwnerPrivate(c, denied, categoryDenied, ambientOwner)
		}
		return val
	}
	return v
}

// Augment validates a read query against the GitHub schema and injects, into every
// repo-scoped selection set, a hidden field revealing that object's repository. It
// returns the rewritten query. An invalid/untypable query yields an error so the
// caller can fail closed.
func (s *Schema) Augment(query string) (string, error) {
	// Bound the parse before gqlparser.LoadQuery: LoadQuery re-parses with an UNLIMITED token
	// limit, which a deeply nested query drives into a fatal stack overflow before validation
	// ever runs (the same crash the classifier guards — Augment is reached on the request path
	// regardless of the classifier's verdict). A token-bounded pre-parse fails closed on such
	// input, and any query that passes it is small enough that LoadQuery's re-parse is bounded too.
	preDoc, perr := parser.ParseQueryWithTokenLimit(&ast.Source{Input: query}, maxAugmentTokens)
	if perr != nil {
		return "", fmt.Errorf("parsing query: %s", perr.Error())
	}
	// Bound the fragment graph BEFORE the validator's Walk. gqlparser's validator validates every
	// operation AND every fragment DEFINITION as a separate root, each re-walking the fragment-spread
	// subgraph it can reach, so a document of N mutually-/chain-referencing fragments costs ~O(N × edges)
	// — tens of seconds of CPU for a few-hundred-KB body that still fits under maxAugmentTokens (measured:
	// ~35s for 1500 fragments × 15 spreads, ~250KB). Augment runs on EVERY /graphql request before the
	// policy verdict (proxy.go), and the injection/output caps below run only AFTER this Walk, so neither
	// bounds it — a deny-all token could still pin a core for a minute (round-22). Cap the fragment count
	// and the total spread-edge count of the parsed document; over either, fail closed (the caller treats
	// it like an untypable query and the proxy denies). Real queries are orders of magnitude smaller.
	if frags := len(preDoc.Fragments); frags > maxAugmentFragments {
		return "", fmt.Errorf("query has too many fragment definitions (%d > %d)", frags, maxAugmentFragments)
	}
	edges := 0
	for _, op := range preDoc.Operations {
		edges += countFragmentSpreads(op.SelectionSet, 0)
	}
	for _, frag := range preDoc.Fragments {
		edges += countFragmentSpreads(frag.SelectionSet, 0)
	}
	if edges > maxAugmentSpreadEdges {
		return "", fmt.Errorf("query has too many fragment spreads (%d > %d)", edges, maxAugmentSpreadEdges)
	}
	// Validate with the default rules MINUS OverlappingFieldsCanBeMerged (an O(n^2)-per-response-name
	// rule that is a CPU-DoS vector on the request path — see schema.go). The Walk still populates the
	// field definitions augment relies on, and all other rules still run, so an otherwise-invalid query
	// is still rejected and fails closed.
	doc, gerr := gqlparser.LoadQueryWithRules(s.schema, query, s.validationRules)
	if gerr != nil {
		return "", fmt.Errorf("validating query: %s", gerr.Error())
	}
	// Fail closed if the client itself references the reserved marker alias: it could
	// otherwise pre-declare bghRepoTagZ9 in a repo-scoped selection to suppress our
	// injected repository tag and defeat redaction. The same walk bounds nesting depth so
	// augment() below never recurses unboundedly. The caller treats this error like an
	// untypable query, falling back to the classifier's cross-repo-nav denial.
	for _, op := range doc.Operations {
		if usesReservedAlias(op.SelectionSet, 0) {
			return "", fmt.Errorf("query references reserved alias %q or is too deeply nested", markerAlias)
		}
	}
	for _, frag := range doc.Fragments {
		if usesReservedAlias(frag.SelectionSet, 0) {
			return "", fmt.Errorf("query references reserved alias %q or is too deeply nested", markerAlias)
		}
	}
	// Bound the marker injection DURING construction. augment expands every abstract selection to
	// one inline fragment per repo-scoped concrete member (Node alone has ~130), so a query of
	// thousands of repeated abstract selections (node(id:){__typename}, ×thousands) would build a
	// ~200MB AST + tens of seconds of CPU BEFORE the post-serialization output cap below could
	// reject it — a single-client memory+CPU DoS (round-16, a surviving variant of round-15 F5
	// which bounded only the OUTPUT). The budget caps total injected fragments and short-circuits
	// the walk once exceeded, so the transient stays small; over the cap we fail closed (the caller
	// treats it like an untypeable query and the proxy denies).
	budget := &injectionBudget{remaining: maxAugmentInjections}
	for _, op := range doc.Operations {
		root := s.rootTypeName(op.Operation)
		s.augment(&op.SelectionSet, root, budget)
	}
	for _, frag := range doc.Fragments {
		s.augment(&frag.SelectionSet, frag.TypeCondition, budget)
	}
	if budget.exceeded {
		return "", fmt.Errorf("augmented query exceeds the marker-injection budget (%d fragments)", maxAugmentInjections)
	}

	var buf bytes.Buffer
	formatter.NewFormatter(&buf).FormatQueryDocument(doc)
	// Bound the augmented OUTPUT, not just the input token count. Marker injection adds one inline
	// fragment per repo-scoped concrete member of every abstract selection (Node alone has 100+),
	// so a small query of repeated abstract selections (node(id:){__typename}, ×thousands) can
	// expand ~600× — hundreds of MB / tens of seconds of CPU — before any authorization deny, a
	// single-process DoS reachable by any token holder (audit F5). Over the cap, fail closed: the
	// caller treats it like an untypable query and the proxy denies (respFilter==nil → deny).
	if buf.Len() > maxAugmentOutputBytes {
		return "", fmt.Errorf("augmented query too large (%d bytes > %d cap)", buf.Len(), maxAugmentOutputBytes)
	}
	return buf.String(), nil
}

// maxAugmentOutputBytes caps the rewritten query the proxy will forward. Real augmented queries
// are a few KB; this is far above any legitimate document yet bounds the marker-injection blowup.
const maxAugmentOutputBytes = 8 << 20 // 8 MB

// maxAugmentDepth bounds the marker/alias walk; a query deeper than this fails closed.
// Real queries are far shallower, and GitHub itself rejects very deep documents.
const maxAugmentDepth = 256

// maxAugmentInjections caps the total number of marker fragments augment may inject across the
// whole document, bounding the marker-injection blowup during construction (see Augment). Real
// augmented queries inject far fewer (one marker per repo-scoped selection); 50k fragments serialize
// to a few MB, well under maxAugmentOutputBytes, and build in milliseconds. Exceeding it fails closed.
const maxAugmentInjections = 50_000

// injectionBudget bounds how many marker fragments augment may inject. count() is called after each
// append; once the budget is exhausted, exceeded is set and the recursive walk short-circuits.
type injectionBudget struct {
	remaining int
	exceeded  bool
}

func (b *injectionBudget) count(n int) {
	b.remaining -= n
	if b.remaining < 0 {
		b.exceeded = true
	}
}

// maxAugmentTokens bounds Augment's pre-parse so gqlparser.LoadQuery's unlimited re-parse cannot
// stack-overflow on a deeply nested query. Matches the classifier's maxGraphQLTokens — far above
// any real query, far below the recursion depth that crashes the parser.
const maxAugmentTokens = 100_000

// maxAugmentFragments / maxAugmentSpreadEdges bound the fragment graph the validator's Walk re-traverses
// per root (see Augment). Real documents have a few dozen fragments and a few hundred spreads; these
// ceilings sit far above any legitimate query yet keep the worst-case Walk (~fragments × edges) in the
// low-millions of steps (a few ms), closing the O(N²) fragment-graph CPU-DoS (round-22).
const maxAugmentFragments = 1024
const maxAugmentSpreadEdges = 8192

// countFragmentSpreads counts the FragmentSpread nodes declared directly in a selection tree WITHOUT
// following the spreads (that following is exactly what the validator does O(N²) times). It recurses
// only into field and inline-fragment subselections, bounded by maxAugmentDepth — over the depth it
// returns a fail-closed sentinel so a pathologically deep document trips the spread-edge cap rather than
// slipping under it.
func countFragmentSpreads(sels ast.SelectionSet, depth int) int {
	if depth > maxAugmentDepth {
		return maxAugmentSpreadEdges + 1
	}
	n := 0
	for _, sel := range sels {
		switch f := sel.(type) {
		case *ast.FragmentSpread:
			n++
		case *ast.Field:
			n += countFragmentSpreads(f.SelectionSet, depth+1)
		case *ast.InlineFragment:
			// Count the inline fragment itself, not just its sub-spreads (round-45 F3): an inline fragment on a
			// broad interface is the unit the validator's possibleTypes² cost is paid per, so an attacker who
			// packed 12k inline fragments under the spread budget (which ignored them) drove a multi-second
			// validator Walk. Counting them caps that input below maxAugmentSpreadEdges.
			n += 1 + countFragmentSpreads(f.SelectionSet, depth+1)
		}
	}
	return n
}

// usesReservedAlias reports whether any field in the selection tree uses markerAlias as
// its response key (alias, or name when unaliased), or whether the tree exceeds
// maxAugmentDepth. Fragment bodies are checked via their own definitions by the caller,
// so fragment spreads are not followed here.
func usesReservedAlias(sels ast.SelectionSet, depth int) bool {
	if depth > maxAugmentDepth {
		return true
	}
	for _, sel := range sels {
		switch f := sel.(type) {
		case *ast.Field:
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			if strings.HasPrefix(key, markerAlias) || strings.HasPrefix(key, markerTypeAlias) ||
				strings.HasPrefix(key, ownerMarkerAlias) || strings.HasPrefix(key, ownerMemberMarkerPrefix) ||
				strings.HasPrefix(key, userMarkerAlias) || strings.HasPrefix(key, userGistMarkerPrefix) ||
				strings.HasPrefix(key, userOwnContentMarkerPrefix) ||
				strings.HasPrefix(key, ownerContentMarkerPrefix) || strings.HasPrefix(key, ownerSelfMarkerPrefix) {
				// Reserve the whole marker namespace (exact aliases AND the per-member
				// "markerAlias_Type" suffixes augment injects, plus the owner + per-member-field markers),
				// so a client cannot pre-declare a look-alike key to spoof/suppress a tag and defeat redaction.
				return true
			}
			if usesReservedAlias(f.SelectionSet, depth+1) {
				return true
			}
		case *ast.InlineFragment:
			if usesReservedAlias(f.SelectionSet, depth+1) {
				return true
			}
		}
	}
	return false
}

func (s *Schema) rootTypeName(op ast.Operation) string {
	switch op {
	case ast.Mutation:
		if s.schema.Mutation != nil {
			return s.schema.Mutation.Name
		}
	case ast.Subscription:
		if s.schema.Subscription != nil {
			return s.schema.Subscription.Name
		}
	}
	if s.schema.Query != nil {
		return s.schema.Query.Name
	}
	return "Query"
}

// augment recurses first (so injected markers are not themselves descended into), then
// appends the marker if this selection set's type is repo-scoped.
func (s *Schema) augment(sels *ast.SelectionSet, typeName string, budget *injectionBudget) {
	if budget.exceeded {
		return
	}
	for _, sel := range *sels {
		switch f := sel.(type) {
		case *ast.Field:
			if f.Definition != nil && len(f.SelectionSet) > 0 {
				s.augment(&f.SelectionSet, f.Definition.Type.Name(), budget)
			}
		case *ast.InlineFragment:
			tc := f.TypeCondition
			if tc == "" {
				tc = typeName
			}
			s.augment(&f.SelectionSet, tc, budget)
		}
		if budget.exceeded {
			return
		}
	}
	if s.isRepoScoped(typeName) {
		// Repo marker (which repository) + type marker (which resource), so the filter can
		// apply per-resource policy to this object regardless of how it was reached.
		*sels = append(*sels, s.marker(typeName), typenameMarker())
		budget.count(2)
		return
	}
	if s.repoOwnedNoPath[typeName] {
		// A repo-OWNED content type with NO derivable repository path (timeline events like
		// ClosedEvent/CrossReferencedEvent → issues/pulls, DeploymentReview → deployments,
		// IssueFieldSingleSelectOption → issues, …). We cannot tag its repository, but it is reached
		// by navigation from a SAME-repo marked ancestor, so inject ONLY the type marker; the response
		// filter attributes it to the nearest marked ancestor's repository and enforces its
		// per-resource policy there, failing closed if there is no ancestor repo (round-17). Without
		// this it carried NO marker at all and the filter forwarded it unredacted — bypassing e.g.
		// deployments/issues="none" on objects reached by navigation (the navigation analogue of the
		// round-16 node(id:) fail-closed, which only covered direct node-ID addressing).
		*sels = append(*sels, typenameMarker())
		budget.count(1)
		return
	}
	if scalar := s.repoIdentityScalar[typeName]; scalar != "" {
		// A Node type that self-identifies its repository via a SCALAR (nameWithOwner/repositoryName)
		// but has no derivable repo PATH and is not a per-resource content type — the migration/
		// enterprise namespace types RepositoryMigration / EnterpriseRepositoryInfo /
		// UserNamespaceRepository. The node(id:) resolver already fails these closed (round-18 H), but
		// augment never tagged them, so reaching one by NAVIGATION (e.g.
		// organization(login:){repositoryMigrations{nodes{repositoryName state …}}}) forwarded its repo
		// name + migration metadata unredacted (round-20). Inject a repo marker from nameWithOwner
		// ("owner/repo" → authorized against its real repo); for a type whose only scalar is a BARE
		// repositoryName (no owner) inject a TYPE marker only, so the filter attributes it to its nearest
		// marked ancestor and fails CLOSED under a non-repo (org) scope where there is none.
		if scalar == "nameWithOwner" {
			*sels = append(*sels, &ast.Field{Alias: markerAlias, Name: scalar}, typenameMarker())
			budget.count(2)
		} else {
			*sels = append(*sels, typenameMarker())
			budget.count(1)
		}
		return
	}
	if typeName == "Organization" || typeName == "Enterprise" {
		// An Organization/Enterprise object is owner-private but NOT repo-scoped, so it carries no repo
		// marker and the response filter never redacts its member/admin/billing data. The classifier
		// enforces org/enterprise policy only at an org/user/enterprise ROOT; data reached by navigation
		// (organization(){teams{nodes{organization{membersWithRole}}}}, user(){organizations|enterprises},
		// repository().owner) bypassed it (round-25/26). Inject the owner identifier (login/slug) so
		// RedactDeniedOwnerPrivate can enforce policy regardless of the navigation path, plus a per-field
		// RESPONSE-KEY marker for each member-identity field so an alias can't dodge the null (round-26).
		idField := "login"
		memberFields := orgMemberFieldNames
		if typeName == "Enterprise" {
			idField = "slug"
			memberFields = enterpriseMemberFieldNames
		}
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok || !memberFields[f.Name] {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: ownerMemberMarkerPrefix + key, Name: "__typename"})
			budget.count(1)
		}
		// Owner-private CONTENT fields (rulesets/settings/billing/projects/sponsors/…): mark each with its
		// per-resource key so RedactDeniedOwnerPrivate nulls it when that resource is denied, regardless of the
		// navigation path the org/enterprise was reached by — the response-side enforcement the round-37/38
		// request-side scope missed (round-39).
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok {
				continue
			}
			res, ok := ownerContentResource[f.Name]
			if !ok {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: ownerContentMarkerPrefix + resourceCode(res) + "__" + key, Name: "__typename"})
			budget.count(1)
		}
		*sels = append(*sels, &ast.Field{Alias: ownerMarkerAlias, Name: idField})
		budget.count(1)
		return
	}
	if memberFields := memberBearingNonOwnerTypes[typeName]; memberFields != nil {
		// A non-owner type (Team) exposing its owner's member identity: inject ONLY the per-member-field
		// response-key markers — no owner marker — so the filter redacts these fields under the nearest
		// marked owner ANCESTOR's "members" carve-out (round-26 structural; the owner analogue of
		// repoOwnedNoPath ambient attribution).
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok || !memberFields[f.Name] {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: ownerMemberMarkerPrefix + key, Name: "__typename"})
			budget.count(1)
		}
		// Team also carries its owning org's CONTENT (projectsV2/projects) one hop down — content-mark those
		// too so a projects="none" carve-out is enforced under the ambient org (round-40).
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok {
				continue
			}
			res := contentBearingNonOwnerResource(typeName, f.Name)
			if res == "" {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: ownerContentMarkerPrefix + resourceCode(res) + "__" + key, Name: "__typename"})
			budget.count(1)
		}
		return
	}
	if contentBearingNonOwnerTypes[typeName] {
		// A NON-owner type that carries its enclosing owner's CONTENT (EnterpriseOwnerInfo reached via
		// enterprise(){ownerInfo}; EnterpriseUserAccount via enterprise(){members} → its org-membership
		// inventory). Content-mark each field with its resource, attributed to the ambient owner — the content
		// analogue of memberBearingNonOwnerTypes (round-39 EnterpriseOwnerInfo; round-40 the rest).
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok {
				continue
			}
			res := contentBearingNonOwnerResource(typeName, f.Name)
			if res == "" {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: ownerContentMarkerPrefix + resourceCode(res) + "__" + key, Name: "__typename"})
			budget.count(1)
		}
		return
	}
	if res := s.ownerOwnedContentResource[typeName]; res != "" {
		// An owner-OWNED content TYPE (ProjectV2/classic Project/…) reached by navigation (issue.projectItems.
		// project) — NOT via node(id:) (already fail-closed) nor via the content-marked organization(){projectsV2}
		// field. Self-mark it with its resource; RedactDeniedOwnerPrivate fails it closed when there is no marked
		// owner ancestor (e.g. reached under a repo) or that owner's resource is denied (round-41 finding-1).
		*sels = append(*sels, &ast.Field{Alias: ownerSelfMarkerPrefix + resourceCode(res), Name: "__typename"})
		budget.count(1)
		return
	}
	if typeName == "User" {
		// A User reached by CONCRETE navigation (ReleaseAsset.uploadedBy, Release.author,
		// RepositoryCollaboratorEdge.node, *.user, …) or an `... on User { … }` inline fragment (augment
		// recurses into it as concrete User) carrying an owner-PRIVATE field. Mark it (and those fields)
		// ONLY when such a field is selected — so the ubiquitous Actor/author User reached as plain {login}
		// is NOT marked (no coarse over-redaction), but a DENIED user's sponsors financials / verified-domain
		// emails are nulled. This is the concrete/inline-fragment sibling of round-28's interface-only fix
		// (round-29). The round-28 abstract userMarkerFragment still covers a private field selected as an
		// interface COMMON field with no inline fragment.
		injected := false
		for _, sel := range *sels {
			f, ok := sel.(*ast.Field)
			if !ok || !userPrivateFields[f.Name] {
				continue
			}
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			*sels = append(*sels, &ast.Field{Alias: userPrivateMarkerPrefix(f.Name) + key, Name: "__typename"})
			budget.count(1)
			injected = true
		}
		if injected {
			*sels = append(*sels, &ast.Field{Alias: userMarkerAlias, Name: "login"})
			budget.count(1)
		}
		return
	}
	// Abstract type (interface/union): the runtime object is one of its concrete members.
	// Interfaces/unions are NEVER themselves repo-scoped (deriveRepoPaths only pathes concrete
	// types), so a selection written against the abstract type — `... on Comment { body }`,
	// `subject { ... }` where subject: ReferencedSubject, `node(id:){ ... }` — received no
	// marker and the filter forwarded a cross-repo object untagged (round-12 audit H1). Inject
	// a marker fragment for every repo-scoped concrete possibility, exactly as
	// buildNodeResolveQuery covers all repo-scoped Node types for nodes(ids:): whichever
	// concrete type comes back at runtime self-identifies its repository and gets redacted if
	// denied. Members that are not repo-scoped add nothing.
	members := s.repoScopedMembers(typeName)
	for _, member := range members {
		*sels = append(*sels, s.memberMarkerFragment(member))
	}
	budget.count(len(members))
	// Repo-owned-no-path members of the abstract type get a TYPE-only marker fragment (round-17),
	// so a selection that could resolve to one (e.g. an interface common field, or a union member
	// reached without an explicit inline fragment) is still attributed by the filter to its nearest
	// marked ancestor's repository — mirroring the repo-scoped member injection above.
	noPathMembers := s.repoOwnedNoPathMembers(typeName)
	for _, member := range noPathMembers {
		*sels = append(*sels, s.memberTypeMarkerFragment(member))
	}
	budget.count(len(noPathMembers))
	// Repo-identity-scalar members (RepositoryMigration / Enterprise…): a nameWithOwner member gets a
	// repo-marker fragment (authorized against its own repo); a bare-repositoryName member gets a
	// type-marker fragment (attributed to the nearest marked ancestor, fail-closed under an org scope) —
	// mirroring the concrete repoIdentityScalar branch above (round-20).
	idMembers := s.repoIdentityNoPathMembers(typeName)
	for _, member := range idMembers {
		if s.repoIdentityScalar[member] == "nameWithOwner" {
			*sels = append(*sels, s.memberIdentityMarkerFragment(member))
		} else {
			*sels = append(*sels, s.memberTypeMarkerFragment(member))
		}
	}
	budget.count(len(idMembers))
	// Owner (Organization/Enterprise) members of the abstract type: an interface-typed field selected via
	// its COMMON owner-private fields with NO inline fragment (Sponsorship.sponsorable: Sponsorable →
	// monthlyEstimatedSponsorsIncomeInCents; ProjectV2.owner: ProjectV2Owner → projectsV2; ProfileOwner →
	// email) resolves to an Organization that the concrete branch never marked, so a DENIED owner's
	// owner-private data streamed unredacted (round-27). Inject an owner-marker fragment so the resolved
	// owner self-identifies and RedactDeniedOwnerPrivate's base-denied coarse redaction (or members null)
	// fires regardless of the abstract path.
	orig := *sels
	owners := s.ownerMembers(typeName)
	for _, owner := range owners {
		*sels = append(*sels, s.ownerMarkerFragment(owner, orig))
	}
	budget.count(len(owners))
	// User possible type of an interface/union (Sponsorable/ProfileOwner/Actor/…): inject a USER marker +
	// per-field markers ONLY when an owner-private User field is selected, so a DENIED user's sponsors
	// financials / verified-domain emails are nulled — without coarse-redacting the user (it is reached
	// everywhere as an Actor/author) (round-28).
	if s.unionHasUser(typeName) {
		if frag := s.userMarkerFragment(orig); frag != nil {
			*sels = append(*sels, frag)
			budget.count(1)
		}
	}
}

// unionHasUser reports whether an interface/union has User as a possible type.
func (s *Schema) unionHasUser(typeName string) bool {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return false
	}
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if pt.Name == "User" {
			return true
		}
	}
	return false
}

// userMarkerFragment builds `... on User { bghOwnerUserZ9: login <bghOrgMemZ9_<key> per selected private field> }`
// or nil when the sibling selection touches no owner-private User field.
func (s *Schema) userMarkerFragment(siblingSels ast.SelectionSet) *ast.InlineFragment {
	sel := ast.SelectionSet{&ast.Field{Alias: userMarkerAlias, Name: "login"}}
	any := false
	for _, ss := range siblingSels {
		if f, ok := ss.(*ast.Field); ok && userPrivateFields[f.Name] {
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			sel = append(sel, &ast.Field{Alias: userPrivateMarkerPrefix(f.Name) + key, Name: "__typename"})
			any = true
		}
	}
	if !any {
		return nil
	}
	return &ast.InlineFragment{TypeCondition: "User", SelectionSet: sel}
}

// ownerMembers returns the Organization/Enterprise concrete possible types of an interface/union, so an
// abstract selection that could resolve to a denied owner via common fields is marked and redacted.
func (s *Schema) ownerMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if pt.Name == "Organization" || pt.Name == "Enterprise" {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ownerMarkerFragment builds `... on Organization { bghOrgLoginZ9: login <per-selected-member-field markers>
// <per-selected-content-field markers> }` (or Enterprise/slug) for an owner reached through an abstract field
// via its COMMON fields with no inline fragment, so the resolved owner self-identifies and RedactDeniedOwnerPrivate
// gates it (round-27 member markers; round-39 content markers — an owner-private CONTENT field selected as an
// interface COMMON field, e.g. Sponsorable.monthlyEstimatedSponsorsIncomeInCents / ProjectV2Owner.projectsV2,
// resolved to an Organization with no `... on Organization` inline fragment, so the concrete content-marking
// branch never saw it and the per-resource carve-out was bypassed response-side on the abstract path).
func (s *Schema) ownerMarkerFragment(ownerType string, siblingSels ast.SelectionSet) *ast.InlineFragment {
	idField := "login"
	memberFields := orgMemberFieldNames
	if ownerType == "Enterprise" {
		idField = "slug"
		memberFields = enterpriseMemberFieldNames
	}
	sel := ast.SelectionSet{&ast.Field{Alias: ownerMarkerAlias, Name: idField}}
	for _, ss := range siblingSels {
		f, ok := ss.(*ast.Field)
		if !ok {
			continue
		}
		key := f.Alias
		if key == "" {
			key = f.Name
		}
		if memberFields[f.Name] {
			sel = append(sel, &ast.Field{Alias: ownerMemberMarkerPrefix + key, Name: "__typename"})
		}
		if res, ok := ownerContentResource[f.Name]; ok {
			sel = append(sel, &ast.Field{Alias: ownerContentMarkerPrefix + resourceCode(res) + "__" + key, Name: "__typename"})
		}
	}
	return &ast.InlineFragment{TypeCondition: ownerType, SelectionSet: sel}
}

// repoIdentityNoPathMembers returns the repo-identity-scalar concrete object members of an
// interface/union (sorted), so an abstract selection that could resolve to one is tagged and
// attributed/fail-closed by the response filter. Empty for concrete types and for abstract types with
// no such member.
func (s *Schema) repoIdentityNoPathMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if s.repoIdentityScalar[pt.Name] != "" {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// memberIdentityMarkerFragment builds `... on T { bghRepoTagZ9_T: nameWithOwner bghRepoTypeZ9: __typename }`
// for a repoIdentityNoPath concrete type T (one whose self-identifying scalar is nameWithOwner) reached
// through an enclosing abstract selection: T self-identifies its repository and the filter authorizes it
// against that repo. The per-member alias avoids field-merge conflicts with sibling member fragments.
func (s *Schema) memberIdentityMarkerFragment(typeName string) *ast.InlineFragment {
	return &ast.InlineFragment{
		TypeCondition: typeName,
		SelectionSet: ast.SelectionSet{
			&ast.Field{Alias: markerAlias + "_" + typeName, Name: s.repoIdentityScalar[typeName]},
			typenameMarker(),
		},
	}
}

// repoOwnedNoPathMembers returns the repo-owned-but-unattributable concrete object members of an
// interface/union (sorted), so an abstract selection that could resolve to one still gets a type
// marker and is attributed to its nearest marked ancestor by the response filter. Empty for concrete
// types and for abstract types with no such member.
func (s *Schema) repoOwnedNoPathMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if s.repoOwnedNoPath[pt.Name] {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// memberTypeMarkerFragment builds `... on T { bghRepoTypeZ9: __typename }` for a repo-owned-no-path
// concrete type T reached through an enclosing abstract selection: T self-identifies its TYPE (so the
// filter knows its per-resource key) while the filter supplies its repository from the ancestor.
func (s *Schema) memberTypeMarkerFragment(typeName string) *ast.InlineFragment {
	return &ast.InlineFragment{
		TypeCondition: typeName,
		SelectionSet:  ast.SelectionSet{typenameMarker()},
	}
}

// repoScopedMembers returns the repo-scoped concrete object types of an interface/union, sorted
// for deterministic output. Empty for concrete types and for abstract types with no repo-scoped
// member (e.g. Actor = User|Bot|Organization), so no fragment is injected there.
func (s *Schema) repoScopedMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if s.repoScoped[pt.Name] {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// memberMarkerFragment builds `... on T { bghRepoTagZ9: <repoPath> bghRepoTypeZ9: __typename }`
// for a repo-scoped concrete type T. T is a possible type of the enclosing abstract selection,
// so the type condition is always valid where this is injected.
func (s *Schema) memberMarkerFragment(typeName string) *ast.InlineFragment {
	return &ast.InlineFragment{
		TypeCondition: typeName,
		SelectionSet:  ast.SelectionSet{s.markerWithAlias(typeName, markerAlias+"_"+typeName), typenameMarker()},
	}
}

// typenameMarker injects `bghRepoTypeZ9: __typename` so the filter can map the object's
// runtime type to a per-resource key. __typename is valid in every object/interface
// selection and adds negligible cost.
func typenameMarker() *ast.Field {
	return &ast.Field{Alias: markerTypeAlias, Name: "__typename"}
}

// marker builds the hidden repository-identifying field for a repo-scoped type, following
// that type's derived path (Repository → nameWithOwner; RepositoryNode → repository{
// nameWithOwner}; DiscussionComment → discussion{repository{nameWithOwner}}). The outermost
// field carries markerAlias so the filter/round-trip can find and strip it.
func (s *Schema) marker(typeName string) *ast.Field {
	return s.markerWithAlias(typeName, markerAlias)
}

// markerWithAlias builds the repository-identifying field for a repo-scoped type under a chosen
// response key. Concrete objects use the canonical markerAlias; interface/union member fragments
// use a per-member suffixed alias so sibling fragments with differently-shaped paths (scalar
// Repository.nameWithOwner vs object X.repository{…}) don't trip GraphQL field-merge validation.
func (s *Schema) markerWithAlias(typeName, alias string) *ast.Field {
	path := s.repoPath[typeName]
	var inner ast.SelectionSet
	for i := len(path) - 1; i >= 0; i-- {
		f := &ast.Field{Name: path[i].field}
		if len(inner) > 0 {
			if path[i].onType != "" {
				// union/interface hop: narrow to `... on <onType>` before continuing the path
				f.SelectionSet = ast.SelectionSet{&ast.InlineFragment{TypeCondition: path[i].onType, SelectionSet: inner}}
			} else {
				f.SelectionSet = inner
			}
		}
		inner = ast.SelectionSet{f}
	}
	root := inner[0].(*ast.Field)
	root.Alias = alias
	return root
}

// Filter walks a GraphQL JSON response and redacts (replaces with null) any repo-scoped
// object the authorized predicate rejects, then strips the injected markers. authorized
// receives "owner", "repo", the per-resource key derived from the object's runtime __typename
// (PullRequest→"pulls", Issue→"issues", …; "metadata" for the repository container and unmapped
// types), AND the raw __typename so the caller can apply the lenient "keep the repository
// container" rule to the container ONLY, not to metadata-class CONTENT objects (Discussion/
// Milestone/Project/Tag/…) that must satisfy base access like the direct path (audit F1).
// Passing the resource lets per-resource policy (e.g. pulls="none") be enforced on objects
// reached by ANY path — navigation included — not just the entry point.
// Decision is the per-object verdict the filter's predicate returns.
type Decision int

const (
	// Deny redacts the whole object (replaced with null).
	Deny Decision = iota
	// Keep keeps the object and recurses into its children normally.
	Keep
	// KeepShell keeps a repository CONTAINER only structurally: it preserves subtrees that lead to
	// repo-scoped (marked) descendants — the granted children — but strips the container's OWN
	// data: scalar fields (description/sshUrl/diskUsage/isPrivate/…) and non-repo-scoped leaf
	// objects (contributingGuidelines.body/planFeatures/…). Used when a repo is readable in SOME
	// way (CanReadAnything) but its `metadata` resource is denied, so a `base=none` + per-resource
	// grant reached by navigation cannot leak the repo's metadata/content the direct path forbids
	// (audit F3). Only meaningful for the RepositoryContainerType; other types use Keep/Deny.
	KeepShell
)

// Filter is the bool-predicate convenience wrapper (used by tests): allowed→Keep, denied→Deny. The
// proxy uses FilterWithDecision so it can also request KeepShell for leniently-kept containers.
func Filter(resp map[string]any, authorized func(owner, repo, resource, typename string) bool) map[string]any {
	return FilterWithDecision(resp, func(owner, repo, resource, typename string) Decision {
		if authorized(owner, repo, resource, typename) {
			return Keep
		}
		return Deny
	})
}

// FilterWithDecision walks a GraphQL JSON response and applies authorize's per-object Decision to
// every repo-scoped (marked) object, then strips the injected markers.
func FilterWithDecision(resp map[string]any, authorize func(owner, repo, resource, typename string) Decision) map[string]any {
	v := filterValue(resp, authorize, "", "", false)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// filterValue walks the response. ambOwner/ambRepo carry the repository of the nearest enclosing
// marked-and-kept object — the "ambient repository" used to attribute repo-owned objects that cannot
// self-identify their repo (the type-marker-only repoOwnedNoPath objects; see augment). shell is set
// while walking the subtree of a leniently-kept (KeepShell) repository container: in shell mode an
// UNMARKED intermediate object is reduced to a structural shell (its own scalars/marker-free branches
// stripped, only subtrees leading to a granted marked object recursed) so the container's own
// metadata cannot leak through an intermediate the direct path would have denied (round-19 F3). Shell
// mode ends at the first marked (and authorized) object, whose granted subtree is kept in full.
func filterValue(v any, authorize func(owner, repo, resource, typename string) Decision, ambOwner, ambRepo string, shell bool) any {
	switch val := v.(type) {
	case map[string]any:
		childOwner, childRepo := ambOwner, ambRepo
		if tag, ok := repoMarker(val); ok {
			// A repo marker is only injected onto repo-scoped objects, so its presence means this
			// object belongs to a repository. An unparseable marker (anomalous null/malformed
			// repository) fails closed. The resource comes from the runtime type marker; absent/
			// unmapped → "metadata" (base).
			owner, repo, parsed := repoFromMarker(tag)
			typename := markerTypename(val)
			if !parsed {
				return nil
			}
			switch authorize(owner, repo, typeResource(typename), typename) {
			case Deny:
				return nil
			case KeepShell:
				stripMarkers(val)
				return shellPrune(val, authorize, owner, repo)
			default: // Keep
			}
			// A kept repo-scoped object is fully readable and establishes the repository context
			// for its (possibly unmarkable) descendants; its granted subtree leaves shell mode.
			childOwner, childRepo = owner, repo
			shell = false
		} else if typename := markerTypename(val); typename != "" {
			// A repo-OWNED content object with only a TYPE marker and NO repo marker (a
			// repoOwnedNoPath type: timeline events, DeploymentReview, …). It cannot self-identify
			// its repository, so attribute it to the nearest marked ancestor's repository — for these
			// types that ancestor is always the same repo — and enforce its per-resource policy there.
			// Fail closed if there is no ancestor repository to check against (round-17).
			if ambRepo == "" {
				return nil
			}
			if authorize(ambOwner, ambRepo, typeResource(typename), typename) == Deny {
				return nil
			}
			shell = false // an authorized per-resource content object is readable in full
			// A cross-repository event (CrossReferencedEvent) is attributed to its ambient (allowed) repo
			// and kept, but its url/resourcePath URI scalars name the FOREIGN repo that referenced the
			// allowed issue — a denied repo's identity/existence the marker-redaction of `source` does NOT
			// cover (those scalars carry no marker). Null them when they name a repo policy denies (round-22).
			if crossRepoURIScrubTypes[typename] {
				scrubCrossRepoURIScalars(val, authorize, typename)
			}
		} else if shell {
			// An UNMARKED intermediate inside a KeepShell container (e.g. a linked ProjectV2 /
			// DraftIssue — @docsCategory "projects" is deliberately un-markered because projects
			// span repos). Reduce it to a structural shell too: without this it kept its OWN
			// scalars (title/readme/shortDescription/url/…) of a base=none repo when a marked
			// descendant rode along — exactly what the direct repository(secret){projectV2{…}}
			// path denies (round-19 F3).
			return shellPrune(val, authorize, ambOwner, ambRepo)
		}
		stripMarkers(val) // strip injected repo + type markers (whether or not a marker rode along)
		for k, child := range val {
			val[k] = filterValue(child, authorize, childOwner, childRepo, shell)
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = filterValue(child, authorize, ambOwner, ambRepo, shell)
		}
		return val
	default:
		return v
	}
}

// shellPrune keeps a leniently-allowed repository container as a structural shell only (see
// KeepShell). It strips every scalar field (the container's own metadata) and every child whose
// subtree contains no repo-scoped MARKED object (a non-repo-scoped leaf like contributingGuidelines),
// while recursing — via the normal filterValue, which applies each child's own Decision — into
// subtrees that DO contain marked objects (connection wrappers leading to granted issues/pulls).
func shellPrune(container map[string]any, authorize func(owner, repo, resource, typename string) Decision, ambOwner, ambRepo string) any {
	for k, child := range container {
		switch child.(type) {
		case map[string]any, []any:
			if hasMarkerDescendant(child) {
				// Granted children live here; recurse in SHELL mode with the container's repo as
				// the ambient context, so unmarked INTERMEDIATE objects between the container and
				// the granted (marked) leaf are reduced to shells too (round-19 F3) and any
				// repoOwnedNoPath descendants are attributed to this repo.
				container[k] = filterValue(child, authorize, ambOwner, ambRepo, true)
			} else {
				delete(container, k) // pure container-owned data (no marked object beneath)
			}
		default:
			delete(container, k) // scalar → the container's own metadata
		}
	}
	return container
}

// hasMarkerDescendant reports whether v contains, at any depth, an object carrying ANY injected
// marker — a repo marker (a repo-scoped object filterValue authorizes on its own) OR a bare type
// marker (a repoOwnedNoPath object filterValue authorizes against the ambient repo). A KeepShell
// container keeps such subtrees and prunes only its own marker-free scalars/objects.
func hasMarkerDescendant(v any) bool {
	switch val := v.(type) {
	case map[string]any:
		if _, ok := repoMarker(val); ok {
			return true
		}
		if markerTypename(val) != "" {
			return true
		}
		for _, child := range val {
			if hasMarkerDescendant(child) {
				return true
			}
		}
	case []any:
		for _, child := range val {
			if hasMarkerDescendant(child) {
				return true
			}
		}
	}
	return false
}

// RepositoryContainerType is the GraphQL __typename of the repository container object — the one
// repo-scoped type the response filter keeps leniently (whenever the repo is readable in ANY way)
// so a base=none + per-resource grant doesn't null the container and lose its granted children.
// Every OTHER repo-scoped object, including metadata-class content, must satisfy base/per-resource
// access on its own (see the filterGraphQLResponse callback in internal/proxy).
const RepositoryContainerType = "Repository"

// markerTypename returns the runtime __typename injected under markerTypeAlias, or "" if
// absent (which maps to the "metadata" resource — base access).
func markerTypename(val map[string]any) string {
	s, _ := val[markerTypeAlias].(string)
	return s
}

// repoMarker returns the repository marker injected onto an object, if any. augment keys it by
// the canonical markerAlias on a concrete repo-scoped object, or by a per-member suffixed alias
// (markerAlias+"_"+Type) when the object was selected through an interface/union; either way the
// value carries the single nameWithOwner for this object's own repository.
func repoMarker(val map[string]any) (any, bool) {
	if v, ok := val[markerAlias]; ok {
		return v, true
	}
	for k, v := range val {
		if strings.HasPrefix(k, markerAlias+"_") {
			return v, true
		}
	}
	return nil, false
}

// stripMarkers removes every injected marker (the repo marker — exact or per-member suffixed —
// and the type marker) so they never reach the client.
func stripMarkers(val map[string]any) {
	for k := range val {
		if k == markerTypeAlias || k == markerAlias || strings.HasPrefix(k, markerAlias+"_") {
			delete(val, k)
		}
	}
}

// gqlTypeToResource maps a GraphQL object's __typename to the per-resource policy key (the
// same keys internal/classifier and the policy engine use). A type not listed maps to
// "metadata", governed by the rule's base access — so unmapped objects keep the prior
// repo-granular behaviour and no over-broad resource restriction is applied. Only types
// with a single, unambiguous resource are listed.
var gqlTypeToResource = map[string]string{
	"PullRequest":              "pulls",
	"PullRequestReview":        "pulls",
	"PullRequestReviewComment": "pulls",
	"PullRequestReviewThread":  "pulls",
	"PullRequestCommit":        "pulls",
	"Issue":                    "issues",
	"IssueComment":             "issues",
	"Commit":                   "commits",
	"CommitComment":            "commits",
	"Release":                  "releases",
	"ReleaseAsset":             "releases",
	"Ref":                      "branches",
	"Deployment":               "deployments",
	"DeploymentStatus":         "deployments",
	"CheckRun":                 "checks",
	"CheckSuite":               "checks",
	// Commit statuses are the "checks" resource (the classifier maps REST `statuses`→checks).
	// They are reached via commit.status / commit.statusCheckRollup, whose parent Commit is a
	// DIFFERENT resource (commits), so without these a checks="none" rule would not redact
	// commit-status data (CI state, target URLs) read over GraphQL.
	"Status":            "checks",
	"StatusContext":     "checks",
	"StatusCheckRollup": "checks",
	"Tree":              "contents",
	"Blob":              "contents",
	// Branch protection config is the "branches" resource (REST: /branches/{b}/protection).
	// Reached directly via repository().branchProtectionRules, so it is gated only by repo
	// metadata unless mapped here.
	"BranchProtectionRule": "branches",
}

func typeResource(typename string) string {
	if r, ok := gqlTypeToResource[typename]; ok {
		return r
	}
	return "metadata"
}

// ResourceForType returns the per-resource policy key for a GraphQL object's runtime type
// (PullRequest→"pulls", Issue→"issues", …), or "" when the type maps to no specific resource.
// The proxy uses it to derive a node-ID mutation's per-resource key from the node's REAL,
// GitHub-confirmed type rather than from the mutation field's NAME — so e.g. addComment on a
// pull request is "pulls" and on an issue is "issues", instead of the name-substring guess
// (gqlMutationResource) that returns "" for either and let the write dodge a per-resource rule.
// It is backed by the schema-derived @docsCategory map (deriveTypeResources), so coverage tracks
// the embedded schema rather than a hand-maintained list (round-15).
func (s *Schema) ResourceForType(typename string) string {
	return s.typeRes[typename] // "" when the type maps to no specific resource; caller falls back to the name guess
}

// FilterResource is the per-resource key the RESPONSE FILTER enforces on a repo-scoped object of the
// given runtime type — the same schema-derived mapping as ResourceForType, but defaulting to
// "metadata" (base access) for types with no specific resource. The proxy's response-filter callback
// uses this so per-resource policy (e.g. deployments="none") is enforced on every object whose
// @docsCategory names a real resource, not just the ~30 types an older hand map happened to list.
func (s *Schema) FilterResource(typename string) string {
	if r := s.typeRes[typename]; r != "" {
		return r
	}
	return "metadata"
}

// crossRepoURIScrubTypes are repoOwnedNoPath timeline-event types that are kept by ambient attribution
// but ALSO expose url/resourcePath URI scalars naming a DIFFERENT (cross-repository) repo than their
// ambient one — CrossReferencedEvent, whose url/resourcePath point at the FOREIGN issue/PR that
// cross-referenced the allowed issue. The marked `source` content object is redacted normally, but these
// sibling scalars would leak the foreign repo's identity/existence (round-22). TestCrossRepoURIScrubCoverage
// asserts this equals the schema-derived set (repoOwnedNoPath ∩ has isCrossRepository ∩ has url|resourcePath).
var crossRepoURIScrubTypes = map[string]bool{"CrossReferencedEvent": true}

// scrubCrossRepoURIScalars nulls a kept cross-repository event's url/resourcePath scalars when they name
// a repository policy DENIES. The event itself is authorized against its ambient (allowed) repo, but these
// scalars point at the FOREIGN referencing issue/PR, so they must be checked against THAT repo. An
// unparseable value fails closed (nulled); a same-repo reference parses to the allowed repo → Keep → kept.
func scrubCrossRepoURIScalars(val map[string]any, authorize func(owner, repo, resource, typename string) Decision, typename string) {
	// VALUE-driven (not key-driven): scan EVERY string field, because a client ALIAS (`leak: url`) moves the
	// scalar off its canonical key, dodging a key-name lookup — the round-26/36 alias class, surfaced again
	// here (round-37). Null any field whose value parses to an issue/PR ref in a repo the policy denies.
	for k, v := range val {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		if owner, repo, parsed := repoFromIssueOrPullRef(s); parsed && authorize(owner, repo, typeResource(typename), typename) == Deny {
			val[k] = nil
		}
	}
	// Preserve the round-22 canonical-key FAIL-CLOSED: a `url`/`resourcePath` that does not cleanly parse to
	// an ALLOWED repo is nulled even when the value-driven scan could not classify it.
	for _, field := range []string{"url", "resourcePath"} {
		s, ok := val[field].(string)
		if !ok || s == "" {
			continue
		}
		if owner, repo, parsed := repoFromIssueOrPullRef(s); !parsed || authorize(owner, repo, typeResource(typename), typename) == Deny {
			val[field] = nil
		}
	}
}

// repoFromIssueOrPullRef extracts (owner, repo) from a GitHub issue/PR web URL or resource path —
// "https://github.com/{owner}/{repo}/issues/{n}", ".../pull/{n}", or the host-relative
// "/{owner}/{repo}/issues/{n}" form. It returns ok=false for any other shape so the caller fails closed;
// requiring a known repo subresource as the third path segment keeps the parse unambiguous (a non-repo
// path like /orgs/{org}/... never mis-parses to an (owner, repo)).
func repoFromIssueOrPullRef(s string) (owner, repo string, ok bool) {
	if i := strings.Index(s, "://"); i >= 0 {
		j := strings.IndexByte(s[i+3:], '/')
		if j < 0 {
			return "", "", false
		}
		s = s[i+3+j:] // drop scheme://host, keep the path
	}
	parts := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	switch parts[2] {
	case "issues", "pull", "pulls", "discussions", "commit", "commits":
		return parts[0], parts[1], true
	}
	return "", "", false
}

// orgMemberIdentityScalars are the fields that, on a type reachable from an Organization connection,
// expose a member's/owner's identity — the data a [org.permissions] members="none" carve-out hides.
var orgMemberIdentityScalars = map[string]bool{
	"login": true, "email": true, "actorLogin": true, "actorIp": true, "userLogin": true, "userName": true,
}

// OrgMemberIdentityFields returns every Organization field whose return type — followed one hop into a
// connection's `nodes`/`edges.node` element and expanded through interface/union members — exposes a
// member/owner identity scalar (login/email/IP). The classifier maps each of these to the "members"
// per-resource key (or justifies it as public); a coverage test asserts that mapping stays complete, so a
// schema refresh adding another member-identity org field (the round-21 mannequins / round-22 auditLog
// class) cannot silently bypass members="none" over GraphQL. RETURNS them sorted.
func (s *Schema) OrgMemberIdentityFields() []string {
	org := s.schema.Types["Organization"]
	if org == nil {
		return nil
	}
	unwrap := func(t *ast.Type) string {
		for t.Elem != nil {
			t = t.Elem
		}
		return t.Name()
	}
	concretes := func(name string) []string {
		def := s.schema.Types[name]
		if def == nil {
			return nil
		}
		if def.Kind == ast.Object {
			return []string{name}
		}
		var cs []string
		for _, pt := range s.schema.PossibleTypes[name] {
			cs = append(cs, pt.Name)
		}
		return cs
	}
	exposesIdentity := func(typeName string) bool {
		for _, c := range concretes(typeName) {
			def := s.schema.Types[c]
			if def == nil {
				continue
			}
			for _, f := range def.Fields {
				if orgMemberIdentityScalars[f.Name] {
					return true
				}
			}
		}
		return false
	}
	var out []string
	for _, f := range org.Fields {
		rt := unwrap(f.Type)
		if rt == "Repository" || rt == "RepositoryConnection" {
			continue // repo-scoped — governed by the response filter / repo scope, not member identity
		}
		elem := rt
		if def := s.schema.Types[rt]; def != nil {
			for _, ff := range def.Fields {
				if ff.Name == "nodes" || ff.Name == "edges" {
					et := unwrap(ff.Type)
					if ff.Name == "edges" {
						if ed := s.schema.Types[et]; ed != nil {
							for _, ef := range ed.Fields {
								if ef.Name == "node" {
									et = unwrap(ef.Type)
								}
							}
						}
					}
					if exposesIdentity(et) {
						elem = et
					}
				}
			}
		}
		if exposesIdentity(elem) {
			out = append(out, f.Name)
		}
	}
	sort.Strings(out)
	return out
}

// IsKnownNodeObjectType reports whether typename is an OBJECT type implementing Node that this
// embedded schema recognizes. The node resolver fails closed on a resolved node whose __typename is
// NOT recognized here (live schema drift), instead of treating it as a constraint-free non-repo node.
func (s *Schema) IsKnownNodeObjectType(typename string) bool {
	return s.nodeTypes[typename]
}

// IsKnownObjectType reports whether typename is an OBJECT type the embedded schema recognizes (not just
// Node implementors — repo-scoped leaf content like Submodule is not a Node). The response filter denies
// a repo-marked object whose runtime __typename is unknown (live schema drift) rather than authorize it
// against the lenient "metadata" FilterResource default, mirroring the node resolver's drift
// fail-closed (round-20).
func (s *Schema) IsKnownObjectType(typename string) bool {
	def := s.schema.Types[typename]
	return def != nil && def.Kind == ast.Object
}

// IsBareNameRepoIdentityType reports whether typename is a repoIdentityNoPath type whose ONLY
// repo-identity scalar is a BARE repositoryName (no owner) — RepositoryMigration today. Such a type
// cannot self-derive its (owner, repo), and — unlike a repoOwnedNoPath CONTENT type, which genuinely
// belongs to its enclosing repository — it is an ORG-level record naming a DIFFERENT repository. So
// ambient attribution to the nearest marked ancestor is UNSOUND: reached via
// repository(owner,name){ owner{ ...on Organization{ repositoryMigrations{ nodes{ repositoryName } } } } }
// the migration node sits under the OUTER repository's marker (ambRepo = the allowed path repo) and
// the round-20 type-marker ambient attribution would KEEP it, leaking a DENIED repo's name + migration
// failure/log metadata. The response filter therefore redacts it UNCONDITIONALLY (round-21), matching
// the node(id:) (round-18 H) and organization-root (round-20) entry paths that already fail it closed.
func (s *Schema) IsBareNameRepoIdentityType(typename string) bool {
	return s.repoIdentityScalar[typename] == "repositoryName"
}

// repoFromMarker extracts owner/repo from a marker value. The marker subtree contains only
// the path to a single nameWithOwner (a bare "owner/repo" string for Repository, or a
// nested object like {repository:{nameWithOwner:"owner/repo"}} or {discussion:{repository:
// {nameWithOwner:"owner/repo"}}}), so the repository is the one "owner/repo" string within.
func repoFromMarker(tag any) (owner, repo string, ok bool) {
	nwo := findNameWithOwner(tag)
	if i := strings.IndexByte(nwo, '/'); i > 0 && i < len(nwo)-1 {
		return nwo[:i], nwo[i+1:], true
	}
	return "", "", false
}

// findNameWithOwner returns the single "owner/repo" string within a marker value, recursing
// through the nested objects the marker path produces. A null/absent link (e.g. a comment
// whose discussion is null) yields "" → the caller redacts (fail closed).
func findNameWithOwner(v any) string {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "/") {
			return t
		}
	case map[string]any:
		for _, child := range t {
			if s := findNameWithOwner(child); s != "" {
				return s
			}
		}
	}
	return ""
}

// SchemaType exposes a named type definition from the embedded schema (for cross-package coverage tests
// like the classifier's viewer-private-field guard). Returns nil if the type is unknown.
func SchemaType(s *Schema, name string) *ast.Definition { return s.schema.Types[name] }

// TypeMembers returns the concrete possible-type names of an interface or union (the members a selection
// against it could resolve to), or nil for a concrete type. Used by the viewer-private coverage guard to
// descend a union/interface element (e.g. PinnableItem = Gist | Repository) into its members so a private
// member one structural hop deep is still forced into the front gate (round-36).
func TypeMembers(s *Schema, name string) []string {
	var out []string
	for _, pt := range s.schema.PossibleTypes[name] {
		out = append(out, pt.Name)
	}
	sort.Strings(out)
	return out
}
