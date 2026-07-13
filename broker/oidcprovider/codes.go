package oidcprovider

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// DefaultCodeTTL is the spec-mandated authorization-code lifetime — 60s,
// single-use. Aligns with the broker's consumed-nonces replay-defense.
const DefaultCodeTTL = 60 * time.Second

// authCode is the in-memory record backing a live authorization code.
// The `consumed` flag flips true on first token-endpoint exchange; a
// second exchange returns invalid_grant (AC-06).
type authCode struct {
	code                string
	clientID            string
	redirectURI         string
	sub                 string
	scope               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	expiresAt           time.Time
	consumed            bool
}

// codeStore is a threadsafe in-memory store for pending auth codes.
// Broker is a single-process systemd unit; a restart flushes pending
// codes, which is acceptable at 60s TTL.
type codeStore struct {
	mu   sync.Mutex
	rows map[string]*authCode
	now  func() time.Time
	ttl  time.Duration
}

func newCodeStore(now func() time.Time, ttl time.Duration) *codeStore {
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	if now == nil {
		now = time.Now
	}
	return &codeStore{rows: map[string]*authCode{}, now: now, ttl: ttl}
}

// mint creates a fresh single-use auth code. code is 32 bytes of crypto
// random → base64url — 256 bits of entropy, plenty for a 60s ceiling.
func (s *codeStore) mint(clientID, redirectURI, sub, scope, nonce, codeChallenge, codeChallengeMethod string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.rows[code] = &authCode{
		code:                code,
		clientID:            clientID,
		redirectURI:         redirectURI,
		sub:                 sub,
		scope:               scope,
		nonce:               nonce,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		expiresAt:           s.now().Add(s.ttl),
	}
	return code, nil
}

// consume returns the row for `code` iff it exists, is unconsumed, and is
// not expired. It marks the row consumed atomically so a replay returns
// ok=false. Second return value distinguishes "unknown code" from "replay":
// unknown → (nil, false); replay/expired → (nil, false); success → (row, true).
func (s *codeStore) consume(code string) (*authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[code]
	if !ok {
		return nil, false
	}
	if row.consumed {
		return nil, false
	}
	if s.now().After(row.expiresAt) {
		return nil, false
	}
	row.consumed = true
	return row, true
}

// gcLocked drops rows whose expiresAt is more than 5 minutes in the past.
// Called on every mint — amortized O(1) at low cardinality. Must be
// invoked with s.mu already held.
func (s *codeStore) gcLocked() {
	cutoff := s.now().Add(-5 * time.Minute)
	for code, row := range s.rows {
		if row.expiresAt.Before(cutoff) {
			delete(s.rows, code)
		}
	}
}

// len returns the current row count (diagnostic, tests).
func (s *codeStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}
