// Package loginflow turns the proxy into a tiny OAuth identity provider so a client can run
// the normal `gh auth login` flow against it. The proxy authenticates the operator by
// driving GitHub's own device flow (gh's public OAuth app — no app registration), requires
// the authenticating GitHub login to match the custodian token's owner, lets the operator
// pick a policy, then mints a bgh_ proxy token and hands it to gh as the "access token".
package loginflow

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type grantStatus int

const (
	statusPending       grantStatus = iota // created; awaiting GitHub authentication
	statusAuthenticated                    // GitHub login verified == custodian owner
	statusApproved                         // policy chosen, proxy token minted
	statusDenied                           // GitHub login was not the custodian owner
)

// grant is one in-progress `gh auth login` against the proxy. Outer fields face the gh
// client; the gh* fields hold the inner GitHub device flow that authenticates the operator.
type grant struct {
	id   string // opaque handle the authorize page uses for its AJAX calls
	flow string // "device" | "web"

	// outer (gh <-> proxy)
	userCode    string // device: shown to client; operator confirms it matches their terminal
	deviceCode  string // device: gh polls /access_token with this
	state       string // web: gh's state param
	redirectURI string // web: gh's localhost callback
	authCode    string // web: code we mint on approval; gh exchanges it at /access_token

	// inner (proxy <-> github), populated when the operator starts GitHub auth
	ghDeviceCode string
	ghInterval   int

	login     string // verified GitHub login (once authenticated)
	status    grantStatus
	secret    string // minted bgh_ token (once approved)
	expiresAt time.Time
}

type grantStore struct {
	mu     sync.Mutex
	grants map[string]*grant // keyed by grant.id
	ttl    time.Duration
	stopCh chan struct{}
}

func newGrantStore(ttl time.Duration) *grantStore {
	s := &grantStore{grants: make(map[string]*grant), ttl: ttl, stopCh: make(chan struct{})}
	go s.sweepLoop()
	return s
}

func (s *grantStore) stop() { close(s.stopCh) }

// remove deletes a grant by id (used for one-time issuance: once the minted secret is handed
// to gh, the grant is consumed so a replayed token exchange can't fetch it again).
func (s *grantStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, id)
}

// add stamps the grant with an id + expiry and stores it.
func (s *grantStore) add(g *grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.id = randHex(16)
	g.expiresAt = time.Now().Add(s.ttl)
	s.grants[g.id] = g
}

// withGrant runs fn under the store lock against the grant matching `match`, returning
// whether one was found (and not expired). Holding the lock during fn keeps each grant's
// state-machine transitions atomic against concurrent polls.
func (s *grantStore) withGrant(match func(*grant) bool, fn func(*grant)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, g := range s.grants {
		if g.expiresAt.After(now) && match(g) {
			fn(g)
			return true
		}
	}
	return false
}

func byID(id string) func(*grant) bool {
	return func(g *grant) bool { return id != "" && g.id == id }
}
func byUserCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && g.userCode == code }
}
func byDeviceCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && g.deviceCode == code }
}
func byState(state string) func(*grant) bool {
	return func(g *grant) bool { return state != "" && g.flow == "web" && g.state == state }
}
func byAuthCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && g.authCode == code }
}

func (s *grantStore) sweepLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, g := range s.grants {
				if !g.expiresAt.After(now) {
					delete(s.grants, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randUserCode returns a human-friendly device code like "BCDF-GHJK" from an
// ambiguity-free alphabet (no 0/O/1/I), matching the shape gh expects to display.
func randUserCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
	}
	return string(out)
}
