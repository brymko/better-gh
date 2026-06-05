// Package loginflow turns the proxy into a tiny OAuth identity provider so a client can run
// the normal `gh auth login` flow against it. The proxy authenticates the operator by
// driving GitHub's own device flow (gh's public OAuth app — no app registration), requires
// the authenticating GitHub login to match the custodian token's owner, lets the operator
// pick a policy, then mints a bgh_ proxy token and hands it to gh as the "access token".
package loginflow

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

// maxLiveGrants bounds the in-memory grant store. /login/device/code and /ui/api/start are
// UNAUTHENTICATED (they are the token-acquisition surface), so without a cap an attacker who can
// reach the listener could grow the map without bound (round-12 audit M1). At the cap, new grants
// are refused (429) until the TTL sweep frees space; legitimate sign-in volume is far below it.
const maxLiveGrants = 2048

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

	// inner GitHub device flow that authenticates the operator — driven in the background by
	// runGitHubAuth (which reuses oauth.DeviceFlow); the page only polls this grant's status.
	started bool // GitHub auth goroutine has been launched

	login      string // verified GitHub login (once authenticated)
	status     grantStatus
	denyReason string // human-readable reason shown to the page when status == statusDenied
	secret     string // minted bgh_ token (once approved)
	expiresAt  time.Time
	cancel     context.CancelFunc // cancels the background device-flow goroutine, if one is running

	// browserSecret binds this grant to the browser that started it (set in an HttpOnly cookie).
	// Consuming the grant — minting a token (apiApprove) or an owner session (apiSession), and
	// recovering grant_id for an already-started grant (apiBegin) — requires presenting it, so a
	// leaked/guessed grant_id or user_code is not by itself enough to mint or hijack a session
	// (audit F2). 256-bit, crypto/rand.
	browserSecret string
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
// to gh, the grant is consumed so a replayed token exchange can't fetch it again). It cancels
// the grant's background device-flow goroutine so cleanup actually stops the github.com polling.
func (s *grantStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.grants[id]; ok && g.cancel != nil {
		g.cancel()
	}
	delete(s.grants, id)
}

// add stamps the grant with an id + expiry and stores it, unless the store is at capacity (in
// which case it returns false and the caller responds 429 — see maxLiveGrants).
func (s *grantStore) add(g *grant) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.grants) >= maxLiveGrants {
		return false
	}
	g.id = randHex(16)
	g.expiresAt = time.Now().Add(s.ttl)
	s.grants[g.id] = g
	return true
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

// ctEq compares two grant secrets in constant time. The device_code/auth_code/state matchers run at
// the unauthenticated (and, for /login/oauth/access_token, un-rate-limited) token-exchange endpoint
// against attacker-supplied values, so they must not leak a prefix-timing oracle via `==`'s early
// exit — matching grantCookieMatches (console.go) and the admin/store secret compares (round-15).
func ctEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func byID(id string) func(*grant) bool {
	return func(g *grant) bool { return id != "" && ctEq(g.id, id) }
}
func byUserCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && ctEq(g.userCode, code) }
}
func byDeviceCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && ctEq(g.deviceCode, code) }
}
func byState(state string) func(*grant) bool {
	return func(g *grant) bool { return state != "" && g.flow == "web" && ctEq(g.state, state) }
}
func byAuthCode(code string) func(*grant) bool {
	return func(g *grant) bool { return code != "" && ctEq(g.authCode, code) }
}

// consume runs fn against the matching grant under the store lock; if fn returns true the grant is
// deleted (and its background goroutine cancelled) atomically in the SAME critical section, so the
// read-and-invalidate of a one-time secret cannot race a concurrent poll into handing the same token
// out twice (round-20). Returns whether a (non-expired) match was found.
func (s *grantStore) consume(match func(*grant) bool, fn func(*grant) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, g := range s.grants {
		if g.expiresAt.After(now) && match(g) {
			if fn(g) {
				if g.cancel != nil {
					g.cancel()
				}
				delete(s.grants, id)
			}
			return true
		}
	}
	return false
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
					if g.cancel != nil {
						g.cancel() // stop the background device-flow goroutine for an expired grant
					}
					delete(s.grants, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// rateLimiter is a fixed-window per-source counter guarding the unauthenticated device-flow
// endpoints (each /ui/api/start or /login/api/begin can launch a 15-min github.com-polling
// goroutine). It resets every window, so its map stays bounded; at the per-window per-source
// limit it denies (the caller responds 429). Behind a TLS-terminating front all requests share
// the front's address, so this also acts as a global cap on device-flow starts.
type rateLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	limit  int
	stopCh chan struct{}
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	l := &rateLimiter{counts: make(map[string]int), limit: limit, stopCh: make(chan struct{})}
	go func() {
		t := time.NewTicker(window)
		defer t.Stop()
		for {
			select {
			case <-l.stopCh:
				return
			case <-t.C:
				l.mu.Lock()
				l.counts = make(map[string]int)
				l.mu.Unlock()
			}
		}
	}()
	return l
}

func (l *rateLimiter) stop() { close(l.stopCh) }

// allow records a hit for key and reports whether it is within the window limit. The map-size
// guard keeps a flood of distinct keys (spoofed sources) from growing it without bound.
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] == 0 && len(l.counts) >= 100_000 {
		return false
	}
	if l.counts[key] >= l.limit {
		return false
	}
	l.counts[key]++
	return true
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A process that cannot get randomness must NOT mint a predictable grant id / device
		// code / auth code / session id. Fail loudly (recovered per-request by net/http) instead
		// of returning zero-filled bytes.
		panic("loginflow: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// randUserCode returns a human-friendly device code like "BCDF-GHJK-MNPQ" from an ambiguity-free
// alphabet (no 0/O/1/I), matching the shape gh expects to display. 12 symbols over a 32-char
// alphabet ≈ 60 bits — widened from 8 (40 bits) so it is not feasibly guessable even though
// grant_id recovery is now additionally cookie-gated (audit F2).
func randUserCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const groups = 3
	b := make([]byte, groups*4)
	if _, err := rand.Read(b); err != nil {
		panic("loginflow: crypto/rand unavailable: " + err.Error())
	}
	out := make([]byte, 0, len(b)+groups-1)
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
	}
	return string(out)
}
