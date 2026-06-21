// Package store — PgSessionStore: Postgres-backed SessionStore.
//
// This wraps *PgStore and satisfies the SessionStore interface.
// It is the audit-truth backend per NF5 — every session write that succeeds
// here is the authoritative record, regardless of Valkey state.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/FJ-Studios/hanko/protocol"
)

// PgSessionStore wraps *PgStore and satisfies SessionStore.
// Construct via NewPgSessionStore.
type PgSessionStore struct {
	pg *PgStore
}

// NewPgSessionStore returns a PgSessionStore wrapping the given PgStore.
func NewPgSessionStore(pg *PgStore) *PgSessionStore {
	return &PgSessionStore{pg: pg}
}

// CreateSession inserts a new session row. On conflict (same id), updates.
func (s *PgSessionStore) CreateSession(sess *protocol.Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload, err := json.Marshal(sess.Payload)
	if err != nil {
		return fmt.Errorf("store: CreateSession marshal payload %s: %w", sess.ID, err)
	}

	_, err = s.pg.pool.Exec(ctx, `
		INSERT INTO sessions (id, sigil_id, type, payload, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE
		  SET sigil_id   = EXCLUDED.sigil_id,
		      type       = EXCLUDED.type,
		      payload    = EXCLUDED.payload,
		      expires_at = EXCLUDED.expires_at`,
		sess.ID, sess.SigilID, string(sess.Type), payload,
		sess.CreatedAt, sess.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("store: CreateSession %s: %w", sess.ID, err)
	}
	return nil
}

// GetSession retrieves a session by ID.
func (s *PgSessionStore) GetSession(id string) (*protocol.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := s.pg.pool.QueryRow(ctx, `
		SELECT id, sigil_id, type, payload, created_at, expires_at
		FROM sessions WHERE id = $1`, id)

	sess := &protocol.Session{}
	var sessionType string
	var payload []byte

	if err := row.Scan(&sess.ID, &sess.SigilID, &sessionType,
		&payload, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("store: session %s not found", id)
		}
		return nil, fmt.Errorf("store: GetSession %s: %w", id, err)
	}

	sess.Type = protocol.SessionType(sessionType)
	if err := json.Unmarshal(payload, &sess.Payload); err != nil {
		sess.Payload = map[string]string{}
	}
	return sess, nil
}

// UpdateSession overwrites an existing session (same upsert as CreateSession).
func (s *PgSessionStore) UpdateSession(sess *protocol.Session) error {
	return s.CreateSession(sess)
}

// DeleteSession removes a session from Postgres by ID.
func (s *PgSessionStore) DeleteSession(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pg.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: DeleteSession %s: %w", id, err)
	}
	return nil
}

// Compile-time assertion: PgSessionStore satisfies SessionStore.
var _ SessionStore = (*PgSessionStore)(nil)
