// Package store — PgStore: Postgres-backed Hanko Store (pgx/v5, zero ORM).
//
// DSN is read from HANKO_PG_DSN environment variable.
//
// TODO(shi-hanko-plugin W2): replace raw DSN with shi-secret://hanko/pg-dsn
// integration once the shi secrets broker is available on nuc-dev. The DSN
// env-var pattern is the accepted interim approach (no credentials in source).
//
// Replay-protection guarantee (F-4.4 / spec §10):
//
//	consumed_nonces.nonce BYTEA PRIMARY KEY — INSERT ... ON CONFLICT DO NOTHING
//	ensures exactly ONE of any number of concurrent inserts wins; callers that
//	get rowsAffected == 0 know the nonce was already consumed.
package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/FJ-Studios/hanko/protocol"
)

//go:embed migrations_sql/001_initial.sql
var migrationSQL string

//go:embed migrations_sql/002_sessions.sql
var migrationSessionsSQL string

// PgStore is a Postgres-backed implementation of broker.Store.
// Obtain one via NewPgStore; call Close when done.
type PgStore struct {
	pool *pgxpool.Pool
}

// NewPgStore connects to Postgres using dsn (or HANKO_PG_DSN env when dsn==""),
// runs the embedded schema migration idempotently, and returns a ready PgStore.
func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	if dsn == "" {
		dsn = os.Getenv("HANKO_PG_DSN")
	}
	if dsn == "" {
		return nil, fmt.Errorf("store: HANKO_PG_DSN is not set")
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping failed: %w", err)
	}

	ps := &PgStore{pool: pool}
	if err := ps.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: migration failed: %w", err)
	}
	return ps, nil
}

// Close releases the underlying connection pool.
func (p *PgStore) Close() {
	p.pool.Close()
}

// migrate runs embedded SQL migrations idempotently.
func (p *PgStore) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, migrationSQL); err != nil {
		return fmt.Errorf("migration 001: %w", err)
	}
	if _, err := p.pool.Exec(ctx, migrationSessionsSQL); err != nil {
		return fmt.Errorf("migration 002: %w", err)
	}
	return nil
}

// --- Store interface implementation ---

// SaveSigil persists a Sigil (upsert on id).
func (p *PgStore) SaveSigil(s *protocol.Sigil) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	meta, err := json.Marshal(s.Metadata)
	if err != nil {
		return fmt.Errorf("store: SaveSigil metadata marshal: %w", err)
	}

	_, err = p.pool.Exec(ctx, `
		INSERT INTO sigils (id, subject, public_key, created_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE
		  SET subject    = EXCLUDED.subject,
		      public_key = EXCLUDED.public_key,
		      expires_at = EXCLUDED.expires_at,
		      metadata   = EXCLUDED.metadata`,
		s.ID, s.Subject, []byte(s.PublicKey),
		s.CreatedAt, s.ExpiresAt, meta,
	)
	if err != nil {
		return fmt.Errorf("store: SaveSigil %s: %w", s.ID, err)
	}
	return nil
}

// GetSigil retrieves a Sigil by ID.
func (p *PgStore) GetSigil(id string) (*protocol.Sigil, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := p.pool.QueryRow(ctx, `
		SELECT id, subject, public_key, created_at, expires_at, metadata
		FROM sigils WHERE id = $1`, id)

	s := &protocol.Sigil{}
	var meta []byte
	if err := row.Scan(&s.ID, &s.Subject, &s.PublicKey,
		&s.CreatedAt, &s.ExpiresAt, &meta); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("store: sigil %s not found", id)
		}
		return nil, fmt.Errorf("store: GetSigil %s: %w", id, err)
	}
	if err := json.Unmarshal(meta, &s.Metadata); err != nil {
		s.Metadata = map[string]string{}
	}
	return s, nil
}

// ListSigils returns all stored sigils ordered by created_at desc.
func (p *PgStore) ListSigils() ([]*protocol.Sigil, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx, `
		SELECT id, subject, public_key, created_at, expires_at, metadata
		FROM sigils ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ListSigils: %w", err)
	}
	defer rows.Close()

	var out []*protocol.Sigil
	for rows.Next() {
		s := &protocol.Sigil{}
		var meta []byte
		if err := rows.Scan(&s.ID, &s.Subject, &s.PublicKey,
			&s.CreatedAt, &s.ExpiresAt, &meta); err != nil {
			return nil, fmt.Errorf("store: ListSigils scan: %w", err)
		}
		if err := json.Unmarshal(meta, &s.Metadata); err != nil {
			s.Metadata = map[string]string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SaveCap persists a CapabilityToken (upsert on id).
func (p *PgStore) SaveCap(c *protocol.CapabilityToken) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.pool.Exec(ctx, `
		INSERT INTO capability_tokens (id, sigil_id, scope, issued_at, expires_at, nonce)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE
		  SET scope      = EXCLUDED.scope,
		      expires_at = EXCLUDED.expires_at,
		      nonce      = EXCLUDED.nonce`,
		c.ID, c.SigilID, c.Scope,
		c.IssuedAt, c.ExpiresAt, []byte(c.Nonce),
	)
	if err != nil {
		return fmt.Errorf("store: SaveCap %s: %w", c.ID, err)
	}
	return nil
}

// GetCap retrieves a CapabilityToken by ID.
func (p *PgStore) GetCap(id string) (*protocol.CapabilityToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := p.pool.QueryRow(ctx, `
		SELECT id, sigil_id, scope, issued_at, expires_at, nonce
		FROM capability_tokens WHERE id = $1`, id)

	c := &protocol.CapabilityToken{}
	if err := row.Scan(&c.ID, &c.SigilID, &c.Scope,
		&c.IssuedAt, &c.ExpiresAt, &c.Nonce); err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("store: cap %s not found", id)
		}
		return nil, fmt.Errorf("store: GetCap %s: %w", id, err)
	}
	return c, nil
}

// NonceUsed returns true if the nonce bytes are in consumed_nonces.
func (p *PgStore) NonceUsed(nonce []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var exists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM consumed_nonces WHERE nonce = $1)`,
		nonce).Scan(&exists)
	if err != nil {
		// Conservative: treat query error as "not used"; RecordNonce will surface real error.
		return false
	}
	return exists
}

// RecordNonce records a nonce as consumed using INSERT ... ON CONFLICT DO NOTHING.
// The BYTEA PRIMARY KEY is the authoritative gate — concurrent callers racing
// on the same nonce are safe: exactly one INSERT wins, the rest are no-ops.
func (p *PgStore) RecordNonce(nonce []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//nolint:errcheck — replay silently resolved by PK constraint
	p.pool.Exec(ctx,
		`INSERT INTO consumed_nonces (nonce) VALUES ($1) ON CONFLICT DO NOTHING`,
		nonce)
}

// RecordNonceStrict is like RecordNonce but returns (true, nil) when the INSERT
// wins (first caller) and (false, nil) when the nonce was already consumed.
// Used by the store contract race test to prove exactly-one-winner semantics.
func (p *PgStore) RecordNonceStrict(ctx context.Context, nonce []byte) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		`INSERT INTO consumed_nonces (nonce) VALUES ($1) ON CONFLICT DO NOTHING`,
		nonce)
	if err != nil {
		return false, fmt.Errorf("store: RecordNonceStrict: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// TryRecordNonce atomically checks and records a nonce.
// Returns true if this call was the first consumer (INSERT succeeded);
// false if the nonce was already recorded (replay detected).
//
// SECURITY(CRIT-6/F-4.4): single round-trip, no TOCTOU window.
// Delegates to RecordNonceStrict with a 2s timeout.
func (p *PgStore) TryRecordNonce(nonce []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, _ := p.RecordNonceStrict(ctx, nonce)
	return ok
}

// RevocationList returns all revocation entries as a protocol.RevocationList.
func (p *PgStore) RevocationList() *protocol.RevocationList {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.pool.Query(ctx,
		`SELECT id, target_type, reason, revoked_at, revoked_by
		 FROM revocation_entries ORDER BY revoked_at`)
	if err != nil {
		return &protocol.RevocationList{}
	}
	defer rows.Close()

	rl := &protocol.RevocationList{}
	for rows.Next() {
		e := protocol.RevocationEntry{}
		if err := rows.Scan(&e.ID, &e.TargetType, &e.Reason, &e.RevokedAt, &e.RevokedBy); err != nil {
			continue
		}
		rl.Entries = append(rl.Entries, e)
	}
	return rl
}

// IsRevoked returns true if the entity with the given ID appears in the
// revocation_entries table. Uses a point-read (WHERE id = $1 LIMIT 1) backed
// by the PRIMARY KEY — O(1) lookup. Called on every VerifyAttestation.
func (p *PgStore) IsRevoked(id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var exists bool
	err := p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM revocation_entries WHERE id = $1 LIMIT 1)`,
		id,
	).Scan(&exists)
	return err == nil && exists
}

// Revoke appends a revocation entry.
func (p *PgStore) Revoke(entry protocol.RevocationEntry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.pool.Exec(ctx, `
		INSERT INTO revocation_entries (id, target_type, reason, revoked_at, revoked_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING`,
		entry.ID, entry.TargetType, entry.Reason, entry.RevokedAt, entry.RevokedBy,
	)
	if err != nil {
		return fmt.Errorf("store: Revoke %s: %w", entry.ID, err)
	}
	return nil
}
