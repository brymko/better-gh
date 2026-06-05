package policy

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"better-gh/internal/classifier"

	"github.com/BurntSushi/toml"
)

type Access int

const (
	AccessNone Access = iota
	AccessRead
	AccessReadWrite
)

func (a *Access) UnmarshalText(text []byte) error {
	switch string(text) {
	case "none":
		*a = AccessNone
	case "read":
		*a = AccessRead
	case "read-write", "readwrite", "write":
		*a = AccessReadWrite
	default:
		return fmt.Errorf("unknown access level: %q", string(text))
	}
	return nil
}

type DefaultMode int

const (
	ModeDeny DefaultMode = iota
	ModeAllow
)

func (m *DefaultMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "deny":
		*m = ModeDeny
	case "allow":
		*m = ModeAllow
	default:
		return fmt.Errorf("unknown default mode: %q", string(text))
	}
	return nil
}

func (a Access) MarshalText() ([]byte, error) {
	return []byte(accessStr(a)), nil
}

func (m DefaultMode) MarshalText() ([]byte, error) {
	switch m {
	case ModeAllow:
		return []byte("allow"), nil
	default:
		return []byte("deny"), nil
	}
}

type Policy struct {
	Defaults Defaults   `toml:"defaults" json:"defaults"`
	Org      []OrgRule  `toml:"org" json:"org"`
	Repo     []RepoRule `toml:"repo" json:"repo"`
}

type Defaults struct {
	Mode     DefaultMode       `toml:"mode" json:"mode"`
	Unscoped map[string]Access `toml:"unscoped,omitempty" json:"unscoped,omitempty"`
}

type OrgRule struct {
	Name        string            `toml:"name" json:"name"`
	Access      Access            `toml:"access" json:"access"`
	Permissions map[string]Access `toml:"permissions,omitempty" json:"permissions,omitempty"`
}

type RepoRule struct {
	Name        string            `toml:"name" json:"name"`
	Access      Access            `toml:"access" json:"access"`
	Permissions map[string]Access `toml:"permissions,omitempty" json:"permissions,omitempty"`
}

type Result struct {
	Allowed bool
	Reason  string
}

func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return ParseTOML(data)
}

// ParseTOML parses a policy from a TOML document (the same shape as policy.toml). The owner
// console's "paste the spec" box uses it so an operator can author a full policy by hand.
func ParseTOML(data []byte) (*Policy, error) {
	var p Policy
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	return &p, nil
}

// ValidateResourceKeys rejects a policy whose REPO rules carry a per-resource key that no request
// can ever match (a typo like "contnets"), which would silently degrade the intended per-resource
// `none` to the rule's BASE access — a fail-open footgun (round-19 D2). Org per-resource keys are
// open-ended (any org subpath segment), so only repo keys are validated. Mint paths and the socket
// policy loader call this so a typo'd key is surfaced as an error instead of silently fail-opening.
func (p *Policy) ValidateResourceKeys() error {
	known := classifier.KnownRepoResourceKeys()
	for _, r := range p.Repo {
		for k := range r.Permissions {
			if !known[k] {
				return fmt.Errorf("repo %q: unknown per-resource key %q (valid keys: %s)", r.Name, k, knownKeyList(known))
			}
		}
	}
	return nil
}

func knownKeyList(known map[string]bool) string {
	keys := make([]string, 0, len(known))
	for k := range known {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func (p *Policy) Evaluate(repo, org string, access classifier.AccessLevel, resource, unscopedCategory string) Result {
	if repo != "" {
		for _, r := range p.Repo {
			// GitHub resolves owner/repo names case-insensitively; match the same
			// way so a re-cased path cannot dodge an exact-match rule.
			if strings.EqualFold(r.Name, repo) {
				if r.Permissions != nil {
					if resource != "" && resource != classifier.ResourceUnknown {
						if permAccess, ok := r.Permissions[resource]; ok {
							if permits(permAccess, access) {
								return Result{Allowed: true}
							}
							return Result{
								Reason: fmt.Sprintf("repo '%s' resource '%s' policy is %s, requested %s", repo, resource, accessStr(permAccess), access),
							}
						}
					}
					// A WRITE whose resource is unrecognized (ResourceUnknown) or indeterminate
					// ("" — e.g. a GraphQL mutation whose field/type maps to no known resource)
					// MUST NOT inherit the rule's base access while per-resource policy is in
					// effect: otherwise an unmapped write (POST .../dispatches over REST, or
					// addComment/addReaction/lockLockable over GraphQL) dodges a per-resource
					// 'none'. Fail closed. Reads still fall back to base (resource-less reads are
					// always at most as powerful as the base read grant).
					if access == classifier.Write && (resource == "" || resource == classifier.ResourceUnknown) {
						return Result{
							Reason: fmt.Sprintf("repo '%s' write to indeterminate/unrecognized resource denied (per-resource policy in effect)", repo),
						}
					}
				}
				if permits(r.Access, access) {
					return Result{Allowed: true}
				}
				return Result{
					Reason: fmt.Sprintf("repo '%s' policy is %s, requested %s", repo, accessStr(r.Access), access),
				}
			}
		}
	}

	if org != "" {
		for _, o := range p.Org {
			if strings.EqualFold(o.Name, org) {
				if o.Permissions != nil {
					if resource != "" && resource != classifier.ResourceUnknown {
						if permAccess, ok := o.Permissions[resource]; ok {
							if permits(permAccess, access) {
								return Result{Allowed: true}
							}
							return Result{
								Reason: fmt.Sprintf("org '%s' resource '%s' policy is %s, requested %s", org, resource, accessStr(permAccess), access),
							}
						}
					}
					// See the repo block: a write with an indeterminate/unrecognized resource
					// must fail closed under a per-resource rule rather than inherit base access.
					if access == classifier.Write && (resource == "" || resource == classifier.ResourceUnknown) {
						return Result{
							Reason: fmt.Sprintf("org '%s' write to indeterminate/unrecognized resource denied (per-resource policy in effect)", org),
						}
					}
				}
				if permits(o.Access, access) {
					return Result{Allowed: true}
				}
				return Result{
					Reason: fmt.Sprintf("org '%s' policy is %s, requested %s", org, accessStr(o.Access), access),
				}
			}
		}
	}

	if repo == "" && org == "" && unscopedCategory != "" && p.Defaults.Unscoped != nil {
		if catAccess, ok := p.Defaults.Unscoped[unscopedCategory]; ok {
			if permits(catAccess, access) {
				return Result{Allowed: true}
			}
			return Result{
				Reason: fmt.Sprintf("unscoped category '%s' policy is %s, requested %s", unscopedCategory, accessStr(catAccess), access),
			}
		}
	}

	if access == classifier.Write && repo == "" && org == "" {
		return Result{Reason: "unscoped write denied"}
	}

	switch p.Defaults.Mode {
	case ModeAllow:
		return Result{Allowed: true}
	default:
		return Result{Reason: "default policy is deny"}
	}
}

// AllowsAnyWrite reports whether the policy could permit a write to anything. The
// proxy uses it to skip the upstream node-resolution call for tokens that can never
// write, so such a token cannot burn the real token's rate limit with doomed mutations.
func (p *Policy) AllowsAnyWrite() bool {
	if p.Defaults.Mode == ModeAllow {
		return true
	}
	for _, a := range p.Defaults.Unscoped {
		if a == AccessReadWrite {
			return true
		}
	}
	for _, o := range p.Org {
		if o.Access == AccessReadWrite {
			return true
		}
		for _, a := range o.Permissions {
			if a == AccessReadWrite {
				return true
			}
		}
	}
	for _, r := range p.Repo {
		if r.Access == AccessReadWrite {
			return true
		}
		for _, a := range r.Permissions {
			if a == AccessReadWrite {
				return true
			}
		}
	}
	return false
}

// AllowsAnyRead reports whether the policy could permit reading anything. Like
// AllowsAnyWrite, the proxy uses it to skip node resolution for tokens that can never
// read at all (avoiding upstream calls that could only be denied).
func (p *Policy) AllowsAnyRead() bool {
	if p.Defaults.Mode == ModeAllow {
		return true
	}
	for _, a := range p.Defaults.Unscoped {
		if a != AccessNone {
			return true
		}
	}
	for _, o := range p.Org {
		if o.Access != AccessNone {
			return true
		}
		for _, a := range o.Permissions {
			if a != AccessNone {
				return true
			}
		}
	}
	for _, r := range p.Repo {
		if r.Access != AccessNone {
			return true
		}
		for _, a := range r.Permissions {
			if a != AccessNone {
				return true
			}
		}
	}
	return false
}

// CanReadAnything reports whether the policy permits reading any part of a repo/org.
// The GraphQL response filter uses it at repo granularity: an object whose repository
// is entirely unreadable is redacted, while one that is readable in any way is kept.
func (p *Policy) CanReadAnything(repo, org string) bool {
	if repo != "" {
		for _, r := range p.Repo {
			if strings.EqualFold(r.Name, repo) {
				if r.Access != AccessNone {
					return true
				}
				for _, a := range r.Permissions {
					if a != AccessNone {
						return true
					}
				}
				return false
			}
		}
	}
	if org != "" {
		for _, o := range p.Org {
			if strings.EqualFold(o.Name, org) {
				if o.Access != AccessNone {
					return true
				}
				for _, a := range o.Permissions {
					if a != AccessNone {
						return true
					}
				}
				return false
			}
		}
	}
	return p.Defaults.Mode == ModeAllow
}

func permits(rule Access, requested classifier.AccessLevel) bool {
	switch rule {
	case AccessNone:
		return false
	case AccessRead:
		return requested == classifier.Read
	case AccessReadWrite:
		return true
	}
	return false
}

func accessStr(a Access) string {
	switch a {
	case AccessNone:
		return "none"
	case AccessRead:
		return "read"
	case AccessReadWrite:
		return "read-write"
	}
	return "unknown"
}
