package store

import (
	"crypto/rand"
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
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Secret    string         `json:"secret"`
	Policy    policy.Policy  `json:"policy"`
	CreatedAt time.Time      `json:"created_at"`
	LastUsed  time.Time      `json:"last_used,omitempty"`
	Revoked   bool           `json:"revoked"`
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
	return os.WriteFile(s.path, data, 0o600)
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

	tok := ProxyToken{
		ID:        hex.EncodeToString(idBytes),
		Name:      name,
		Secret:    hex.EncodeToString(secretBytes),
		Policy:    pol,
		CreatedAt: time.Now().UTC(),
	}

	secret := tok.Secret
	s.tokens = append(s.tokens, tok)
	if err := s.flush(); err != nil {
		s.tokens = s.tokens[:len(s.tokens)-1]
		return nil, "", err
	}
	return &s.tokens[len(s.tokens)-1], secret, nil
}

func (s *Store) Lookup(secret string) *ProxyToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.tokens {
		if s.tokens[i].Secret == secret && !s.tokens[i].Revoked {
			return &s.tokens[i]
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
