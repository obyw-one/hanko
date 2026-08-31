// Package store — ValkeyAugmentedSessionStore: Valkey-first session cache
// with async Postgres mirror (audit truth per NF5).
//
// Key prefix: hanko:session:<id>
// AUTH: VALKEY_HANKO_PASSWORD env var (hanko_user per W5.1 ACL)
// Address: unix:///run/valkey/valkey.sock (default) or host:port
//
// Write path:
//   SETEX hanko:session:<id> → async goroutine mirrors to Postgres
//
// Read path:
//   GET → if hit: ValkeyHit++, return
//         if miss: ValkeyMiss++, PostgresFallback++, read PG, re-populate Valkey
//
// Delete path: DEL Valkey (sync) + DELETE Postgres (sync)
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/valkey-io/valkey-go"

	"github.com/FJ-Studios/hanko/protocol"
)

const valkeyKeyPrefix = "hanko:session:"

// realValkeyBackend wraps a valkey.Client to satisfy MockableValkeyBackend.
type realValkeyBackend struct {
	client valkey.Client
}

func (r *realValkeyBackend) ValkeyCreate(s *protocol.Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("valkey: marshal session %s: %w", s.ID, err)
	}
	ttl := SessionTTL(s.Type)
	cmd := r.client.B().Set().Key(valkeyKeyPrefix + s.ID).Value(string(data)).Ex(ttl).Build()
	return r.client.Do(context.Background(), cmd).Error()
}

func (r *realValkeyBackend) ValkeyGet(id string) (*protocol.Session, error) {
	cmd := r.client.B().Get().Key(valkeyKeyPrefix + id).Build()
	res := r.client.Do(context.Background(), cmd)
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return nil, ErrValkeyMiss
		}
		return nil, fmt.Errorf("valkey: GET %s: %w", id, res.Error())
	}
	raw, err := res.AsBytes()
	if err != nil {
		return nil, fmt.Errorf("valkey: decode %s: %w", id, err)
	}
	var s protocol.Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("valkey: unmarshal session %s: %w", id, err)
	}
	return &s, nil
}

func (r *realValkeyBackend) ValkeyDelete(id string) error {
	cmd := r.client.B().Del().Key(valkeyKeyPrefix + id).Build()
	return r.client.Do(context.Background(), cmd).Error()
}

func (r *realValkeyBackend) Close() {
	r.client.Close()
}

// ValkeyAugmentedSessionStore is a SessionStore that puts Valkey in front
// of a Postgres backend for fast reads and audit persistence.
type ValkeyAugmentedSessionStore struct {
	valkeyBackend MockableValkeyBackend
	pgBackend     SessionStore
	metrics       sessionMetricsAtomic

	// closer is non-nil when we own a real Valkey client (nil in mock mode).
	closer interface{ Close() }
}

// NewValkeyAugmentedSessionStore constructs a store backed by a real Valkey.
//
//   - valkeyAddr: "unix:///run/valkey/valkey.sock" or "host:port"
//   - AUTH: VALKEY_HANKO_PASSWORD env var
func NewValkeyAugmentedSessionStore(valkeyAddr string, pgBackend SessionStore) (*ValkeyAugmentedSessionStore, error) {
	opts := valkey.ClientOption{
		InitAddress: []string{normalizeAddr(valkeyAddr)},
	}

	if pw := os.Getenv("VALKEY_HANKO_PASSWORD"); pw != "" {
		opts.Password = pw
	}

	client, err := valkey.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("store: valkey connect %s: %w", valkeyAddr, err)
	}

	// Ping to surface connection errors early
	if err := client.Do(context.Background(), client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		return nil, fmt.Errorf("store: valkey ping %s: %w", valkeyAddr, err)
	}

	rb := &realValkeyBackend{client: client}
	return &ValkeyAugmentedSessionStore{
		valkeyBackend: rb,
		pgBackend:     pgBackend,
		closer:        rb,
	}, nil
}

// normalizeAddr converts a "unix:///path" address to the form expected by
// valkey-go ("unix:/path") and leaves TCP addresses unchanged.
func normalizeAddr(addr string) string {
	if strings.HasPrefix(addr, "unix://") {
		// valkey-go accepts "unix:/path"
		return "unix:" + strings.TrimPrefix(addr, "unix://")
	}
	return addr
}

// NewValkeyAugmentedSessionStoreFromEnv reads configuration from environment
// variables and returns a ValkeyAugmentedSessionStore. If HANKO_SESSION_STORE
// is not "valkey", returns (nil, nil) — caller falls back to Postgres-only.
//
// Environment variables:
//
//	HANKO_SESSION_STORE     — must equal "valkey" to activate
//	HANKO_VALKEY_ADDR       — default: unix:///run/valkey/valkey.sock
//	VALKEY_HANKO_PASSWORD   — optional AUTH password
func NewValkeyAugmentedSessionStoreFromEnv(pgBackend SessionStore) (*ValkeyAugmentedSessionStore, error) {
	if os.Getenv("HANKO_SESSION_STORE") != "valkey" {
		return nil, nil
	}
	addr := os.Getenv("HANKO_VALKEY_ADDR")
	if addr == "" {
		addr = "unix:///run/valkey/valkey.sock"
	}
	return NewValkeyAugmentedSessionStore(addr, pgBackend)
}

// NewValkeyAugmentedSessionStoreWithMock constructs a ValkeyAugmentedSessionStore
// using a mock Valkey backend. For unit tests only — not for production use.
func NewValkeyAugmentedSessionStoreWithMock(vb MockableValkeyBackend, pgBackend SessionStore) *ValkeyAugmentedSessionStore {
	return &ValkeyAugmentedSessionStore{
		valkeyBackend: vb,
		pgBackend:     pgBackend,
	}
}

// CreateSession writes the session to Valkey (SETEX) and asynchronously
// mirrors it to the Postgres backend. Valkey write errors are counted but do
// not abort — Postgres is attempted regardless (NF5: audit truth).
func (v *ValkeyAugmentedSessionStore) CreateSession(s *protocol.Session) error {
	if err := v.valkeyBackend.ValkeyCreate(s); err != nil {
		v.metrics.valkeyWriteError.Add(1)
		log.Printf("store: ValkeyCreate %s failed (falling through to Postgres): %v", s.ID, err)
	}

	// Async Postgres mirror — never silence errors.
	go func() {
		if err := v.pgBackend.CreateSession(s); err != nil {
			log.Printf("store: Postgres mirror CreateSession %s failed: %v", s.ID, err)
		}
	}()
	return nil
}

// GetSession retrieves a session by ID. Valkey is tried first; on miss the
// Postgres backend is queried and the result is re-populated into Valkey
// (best-effort).
func (v *ValkeyAugmentedSessionStore) GetSession(id string) (*protocol.Session, error) {
	s, err := v.valkeyBackend.ValkeyGet(id)
	if err == nil {
		v.metrics.valkeyHit.Add(1)
		return s, nil
	}

	// Distinguish cache-miss from real error.
	if !errors.Is(err, ErrValkeyMiss) {
		log.Printf("store: ValkeyGet %s error (falling through to Postgres): %v", id, err)
	}
	v.metrics.valkeyMiss.Add(1)
	v.metrics.postgresFallback.Add(1)

	s, err = v.pgBackend.GetSession(id)
	if err != nil {
		return nil, err
	}

	// Best-effort re-populate Valkey.
	go func() {
		if err := v.valkeyBackend.ValkeyCreate(s); err != nil {
			log.Printf("store: ValkeyCreate re-populate %s failed: %v", s.ID, err)
		}
	}()
	return s, nil
}

// UpdateSession overwrites the session in both stores (same semantics as Create).
func (v *ValkeyAugmentedSessionStore) UpdateSession(s *protocol.Session) error {
	if err := v.valkeyBackend.ValkeyCreate(s); err != nil {
		v.metrics.valkeyWriteError.Add(1)
		log.Printf("store: ValkeyCreate (update) %s failed: %v", s.ID, err)
	}

	go func() {
		if err := v.pgBackend.UpdateSession(s); err != nil {
			log.Printf("store: Postgres mirror UpdateSession %s failed: %v", s.ID, err)
		}
	}()
	return nil
}

// DeleteSession removes the session from both Valkey (DEL) and Postgres (sync).
// The Postgres delete is synchronous so callers get a real error on failure.
func (v *ValkeyAugmentedSessionStore) DeleteSession(id string) error {
	if err := v.valkeyBackend.ValkeyDelete(id); err != nil {
		log.Printf("store: ValkeyDelete %s failed (continuing to Postgres): %v", id, err)
	}
	return v.pgBackend.DeleteSession(id)
}

// Metrics returns a snapshot of the current session store counters.
func (v *ValkeyAugmentedSessionStore) Metrics() SessionMetrics {
	return v.metrics.snapshot()
}

// Close closes the underlying Valkey client (no-op in mock mode).
func (v *ValkeyAugmentedSessionStore) Close() {
	if v.closer != nil {
		v.closer.Close()
	}
}
