package policy

import (
	"fmt"
	"os"

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
	var p Policy
	if err := toml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}
	return &p, nil
}

func (p *Policy) Evaluate(repo, org string, access classifier.AccessLevel, resource, unscopedCategory string) Result {
	if repo != "" {
		for _, r := range p.Repo {
			if r.Name == repo {
				if resource != "" && r.Permissions != nil {
					if permAccess, ok := r.Permissions[resource]; ok {
						if permits(permAccess, access) {
							return Result{Allowed: true}
						}
						return Result{
							Reason: fmt.Sprintf("repo '%s' resource '%s' policy is %s, requested %s", repo, resource, accessStr(permAccess), access),
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
			if o.Name == org {
				if resource != "" && o.Permissions != nil {
					if permAccess, ok := o.Permissions[resource]; ok {
						if permits(permAccess, access) {
							return Result{Allowed: true}
						}
						return Result{
							Reason: fmt.Sprintf("org '%s' resource '%s' policy is %s, requested %s", org, resource, accessStr(permAccess), access),
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

	switch p.Defaults.Mode {
	case ModeAllow:
		return Result{Allowed: true}
	default:
		return Result{Reason: "default policy is deny"}
	}
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
