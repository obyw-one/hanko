package oidcprovider

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// DefaultSessionTTL is the hanko-session cookie lifetime after successful
// login. Deliberately short — a fresh login on each MM sign-in is fine
// for the target usage; long-lived sessions belong at the RP.
const DefaultSessionTTL = 30 * time.Minute

// SessionCookieName is the cookie carrying the hanko session token.
const SessionCookieName = "hanko_session"

// sessionRow binds a session cookie value to an authenticated user's Sub
// and cookie expiry.
type sessionRow struct {
	token     string
	sub       string
	expiresAt time.Time
}

// sessionStore is an in-memory session table. Same restart-flushes-state
// posture as codeStore.
type sessionStore struct {
	mu   sync.Mutex
	rows map[string]*sessionRow
	now  func() time.Time
	ttl  time.Duration
}

func newSessionStore(now func() time.Time, ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if now == nil {
		now = time.Now
	}
	return &sessionStore{rows: map[string]*sessionRow{}, now: now, ttl: ttl}
}

// create mints a fresh session token (32 crypto-random bytes → base64url)
// bound to sub, records it, and returns the token + expiry timestamp.
func (s *sessionStore) create(sub string) (token string, expiresAt time.Time, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	expiresAt = s.now().Add(s.ttl)
	s.rows[token] = &sessionRow{token: token, sub: sub, expiresAt: expiresAt}
	return token, expiresAt, nil
}

// lookup returns (sub, true) if token is a live session, else ("", false).
// Silently drops expired sessions on access.
func (s *sessionStore) lookup(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[token]
	if !ok {
		return "", false
	}
	if s.now().After(row.expiresAt) {
		delete(s.rows, token)
		return "", false
	}
	return row.sub, true
}

// revoke drops a session — used for spec's ".oidc.session_revoked" event
// path (session invalidation on user offboarding).
func (s *sessionStore) revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, token)
}

func (s *sessionStore) gcLocked() {
	cutoff := s.now().Add(-5 * time.Minute)
	for tok, row := range s.rows {
		if row.expiresAt.Before(cutoff) {
			delete(s.rows, tok)
		}
	}
}
