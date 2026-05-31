package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	secret := hex.EncodeToString(secretBytes)
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

func (s *Store) TouchLastUsed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].ID == id {
			s.tokens[i].LastUsed = time.Now().UTC()
			_ = s.flush()
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

func (s *Store) Revoke(idOrName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].ID == idOrName || s.tokens[i].Name == idOrName {
			s.tokens[i].Revoked = true
			_ = s.flush()
			return true
		}
	}
	return false
}

func (s *Store) Delete(idOrName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].ID == idOrName || s.tokens[i].Name == idOrName {
			s.tokens = append(s.tokens[:i], s.tokens[i+1:]...)
			_ = s.flush()
			return true
		}
	}
	return false
}
