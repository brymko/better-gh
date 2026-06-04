package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"better-gh/internal/policy"
)

type ProxyToken struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	SecretHash string        `json:"secret_hash"`
	Policy     policy.Policy `json:"policy"`
	CreatedAt  time.Time     `json:"created_at"`
	LastUsed   time.Time     `json:"last_used,omitempty"`
	Revoked    bool          `json:"revoked"`
}

type Store struct {
	path   string
	mu     sync.RWMutex
	tokens []ProxyToken
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("reading store: %w", err)
	}
	if err := json.Unmarshal(data, &s.tokens); err != nil {
		return nil, fmt.Errorf("parsing store: %w", err)
	}
	return s, nil
}

func (s *Store) flush() error {
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temp file then rename so a crash or a concurrent reader never sees a
	// truncated/partial tokens.json (flush runs on every allowed request via TouchLastUsed).
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Create(name string, pol policy.Policy) (*ProxyToken, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, "", err
	}

	// "bgh_" prefix makes a proxy token visually distinguishable from a real GitHub token
	// (gho_/ghp_/github_pat_) — handy when debugging which credential a client is actually
	// using. The prefix is part of the secret and is hashed with it.
	secret := "bgh_" + hex.EncodeToString(secretBytes)
	hash := sha256.Sum256([]byte(secret))

	tok := ProxyToken{
		ID:         hex.EncodeToString(idBytes),
		Name:       name,
		SecretHash: hex.EncodeToString(hash[:]),
		Policy:     pol,
		CreatedAt:  time.Now().UTC(),
	}
	s.tokens = append(s.tokens, tok)
	if err := s.flush(); err != nil {
		s.tokens = s.tokens[:len(s.tokens)-1]
		return nil, "", err
	}
	// Return a copy of the local value, not &s.tokens[...]: a later append/Delete can
	// reallocate or shift the slice, clobbering a pointer into it.
	return &tok, secret, nil
}

func (s *Store) Lookup(secret string) *ProxyToken {
	hash := sha256.Sum256([]byte(secret))
	hexHash := hex.EncodeToString(hash[:])

	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(s.tokens[i].SecretHash), []byte(hexHash)) == 1 && !s.tokens[i].Revoked {
			// Return a COPY, not &s.tokens[i]: the caller uses the result after releasing
			// the lock, and a concurrent Delete shifts the slice in place — a live pointer
			// into it could be repointed to a different token's policy. (Get does the same.)
			tok := s.tokens[i]
			return &tok
		}
	}
	return nil
}

// lastUsedFlushInterval debounces LastUsed persistence. Without it, every allowed GHE
// request rewrites the whole tokens.json (temp+rename) — a client flooding cheap requests
// would amplify into unbounded disk writes and goroutines blocked on them. Persisting at
// most once per interval per token caps that; LastUsed is then accurate to the interval.
const lastUsedFlushInterval = time.Minute

func (s *Store) TouchLastUsed(id string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].ID == id {
			if now.Sub(s.tokens[i].LastUsed) < lastUsedFlushInterval {
				return // recorded recently; skip the rewrite to cap write amplification
			}
			s.tokens[i].LastUsed = now
			if err := s.flush(); err != nil {
				slog.Warn("persisting last-used failed", "id", id, "err", err)
			}
			return
		}
	}
}

func (s *Store) List() []ProxyToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ProxyToken, len(s.tokens))
	copy(out, s.tokens)
	return out
}

func (s *Store) Get(idOrName string) *ProxyToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.tokens {
		if s.tokens[i].ID == idOrName || s.tokens[i].Name == idOrName {
			tok := s.tokens[i]
			return &tok
		}
	}
	return nil
}

// Revoke marks EVERY token whose ID or Name matches as revoked, returning whether any matched
// and any persistence error. Matching all (not just the first) closes a footgun: two tokens can
// share a Name (e.g. `gh auth login` twice defaults to "ghlogin-<login>"), and revoking by name
// must kill them all, not leave a same-named secret live (audit F6). The flush error is returned
// (not swallowed) so a handler can surface a failed persist instead of falsely reporting success;
// a swallowed flush failure followed by a restart would resurrect the revoked token (audit F8).
func (s *Store) Revoke(idOrName string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.tokens {
		if s.tokens[i].ID == idOrName || s.tokens[i].Name == idOrName {
			s.tokens[i].Revoked = true
			found = true
		}
	}
	if !found {
		return false, nil
	}
	return true, s.flush()
}

// Delete removes EVERY token whose ID or Name matches (see Revoke for why all, not first), and
// returns whether any matched plus any persistence error.
func (s *Store) Delete(idOrName string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.tokens[:0]
	found := false
	for _, t := range s.tokens {
		if t.ID == idOrName || t.Name == idOrName {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		return false, nil
	}
	s.tokens = kept
	return true, s.flush()
}
