// Package owner persists the single GitHub account that bootstrapped this proxy and the
// GitHub token captured from their sign-in, which the proxy uses as its upstream custodian
// credential.
//
// Trust-on-first-use: the first sign-in claims the deployment for that GitHub login; every
// later sign-in (web admin panel or `gh auth login`) must be that same login and refreshes
// the captured token. There is no separate BGH_GITHUB_TOKEN step — signing in IS the
// bootstrap (an env/config token, if present, is only a fallback custodian until claimed).
package owner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Login     string    `json:"login"`
	Token     string    `json:"token"` // captured GitHub custodian token
	ClaimedAt time.Time `json:"claimed_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	path          string
	mu            sync.RWMutex
	rec           Record
	fallback      string // custodian used before the owner is claimed (e.g. BGH_GITHUB_TOKEN)
	fallbackLogin string // GitHub login that owns `fallback`, resolved before the first claim
}

// Open loads the owner record from path if it exists. fallbackToken is returned by Token()
// until the deployment is claimed, so a pre-seeded env/config token keeps working.
func Open(path, fallbackToken string) (*Store, error) {
	s := &Store{path: path, fallback: fallbackToken}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading owner file: %w", err)
	}
	if err := json.Unmarshal(data, &s.rec); err != nil {
		return nil, fmt.Errorf("parsing owner file: %w", err)
	}
	return s, nil
}

func (s *Store) Claimed() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.rec.Login != "" }

// Login is the owner's GitHub login, or "" if the deployment is unclaimed.
func (s *Store) Login() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.rec.Login }

// Token is the captured custodian token, or the fallback if not yet claimed.
func (s *Store) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.rec.Token != "" {
		return s.rec.Token
	}
	return s.fallback
}

// HasFallback reports whether a pre-seeded custodian token is configured (so an unclaimed
// deployment is already serving traffic under it).
func (s *Store) HasFallback() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.fallback != "" }

// FallbackOwner is the GitHub login bound to the pre-seeded custodian, or "" if not yet
// resolved. The sign-in path resolves it (viewer{login} of the fallback token) before the
// first claim so a pre-seeded deployment can be claimed only by its own custodian's account.
func (s *Store) FallbackOwner() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.fallbackLogin }

// SetFallbackOwner records the GitHub login that owns the pre-seeded custodian token. It is
// idempotent (later calls with the same value are no-ops) and locks the TOFU claim to that
// identity: with a fallback configured, only this login may claim the deployment.
func (s *Store) SetFallbackOwner(login string) {
	login = strings.TrimSpace(login)
	if login == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallbackLogin = login
}

// SignIn applies a completed GitHub sign-in (login + token). The first call claims the
// deployment for login (TOFU); later calls must match that login and refresh the captured
// token. Returns whether this call claimed the deployment and whether it was accepted; ok is
// false (with nil err) when login is not the owner.
func (s *Store) SignIn(login, token string) (claimed, ok bool, err error) {
	login = strings.TrimSpace(login)
	if login == "" || token == "" {
		return false, false, fmt.Errorf("empty login or token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var candidate Record
	switch {
	case s.rec.Login == "":
		// Unclaimed (TOFU). If a fallback custodian is configured, the deployment may be
		// claimed ONLY by that custodian's own GitHub identity — otherwise the first
		// network-reachable stranger could claim a pre-seeded deployment and swap the
		// custodian (round-18 G). Fail closed if the fallback's owner has not been resolved
		// yet (the sign-in path resolves it before calling SignIn): an unverified fallback
		// must not be claimable. With no fallback, this is the documented open TOFU bootstrap.
		if s.fallback != "" {
			if s.fallbackLogin == "" || !strings.EqualFold(s.fallbackLogin, login) {
				return false, false, nil
			}
		}
		candidate = Record{Login: login, Token: token, ClaimedAt: now, UpdatedAt: now}
		claimed = true
	case strings.EqualFold(s.rec.Login, login):
		candidate = s.rec
		candidate.Token = token
		candidate.UpdatedAt = now
	default:
		return false, false, nil // not the owner of this deployment
	}
	// Persist BEFORE mutating the in-memory record: a persist failure must leave the live
	// owner/custodian state untouched (a failed first claim must not silently claim ownership
	// or swap the custodian in memory while disk says otherwise — round-18 I).
	if perr := s.persistRecord(candidate); perr != nil {
		return claimed, false, perr
	}
	s.rec = candidate
	return claimed, true, nil
}

func (s *Store) persistRecord(rec Record) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
