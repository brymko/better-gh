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
	path     string
	mu       sync.RWMutex
	rec      Record
	fallback string // custodian used before the owner is claimed (e.g. BGH_GITHUB_TOKEN)
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
	switch {
	case s.rec.Login == "":
		s.rec = Record{Login: login, Token: token, ClaimedAt: now, UpdatedAt: now}
		claimed = true
	case strings.EqualFold(s.rec.Login, login):
		s.rec.Token = token
		s.rec.UpdatedAt = now
	default:
		return false, false, nil // not the owner of this deployment
	}
	if perr := s.persist(); perr != nil {
		return claimed, false, perr
	}
	return claimed, true, nil
}

func (s *Store) persist() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
