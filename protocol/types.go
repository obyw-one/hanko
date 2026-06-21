// Package protocol defines the Hanko v0.1 wire types.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own pre-existing internal
// codename, conceived independently. The German startup teamhanko/hanko
// (a passkey/passwordless auth project, AGPL-3) is a completely unrelated
// third-party project. There is zero code, dependency, or design inheritance
// between this codebase and teamhanko/hanko. The phonetic choice (Mo-to /
// Han-ko) was operator-intentional. This codebase is NOT customer-facing.
package protocol

import (
	"time"
)

// Version is the Hanko protocol version string embedded in every
// AttestationEnvelope.
const Version = "hanko/v0.1"

// Sigil is a stable, cryptographically-bound identity assertion for an
// operator, agent, or service. The id is stable across renewals.
//
// Wire format: canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
// base64url-no-padding for PublicKey).
type Sigil struct {
	ID        string            `json:"id"`                    // UUID
	Subject   string            `json:"subject"`               // e.g. "operator:shikki@obyw.one"
	PublicKey []byte            `json:"public_key"`            // Ed25519 public key (32 bytes)
	CreatedAt time.Time         `json:"created_at"`            // RFC3339
	ExpiresAt *time.Time        `json:"expires_at,omitempty"` // null = long-lived operator sigil
	Metadata  map[string]string `json:"metadata"`              // e.g. {"workspace":"obyw-one"}
}

// CapabilityToken is a scoped, time-bounded authorization grant tied to a
// Sigil. The nonce provides replay protection (per-token one-time-use, per
// OQ-4 in hanko-v0.1-protocol spec §10).
//
// Per spec §2.1: expires_at is ALWAYS bounded — no immortal cap tokens.
type CapabilityToken struct {
	ID        string    `json:"id"`         // UUID
	SigilID   string    `json:"sigil_id"`   // UUID of bound Sigil
	Scope     string    `json:"scope"`      // e.g. "shi-secrets:read:ns/key"
	IssuedAt  time.Time `json:"issued_at"`  // RFC3339
	ExpiresAt time.Time `json:"expires_at"` // RFC3339 — always set
	Nonce     []byte    `json:"nonce"`      // 16 random bytes for replay protection
}

// AttestationEnvelope is a signed wrapper binding a Sigil + capability list +
// issuer + expiry into a single verifiable unit. The signature covers the
// canonical JSON of all fields except "signature" itself.
type AttestationEnvelope struct {
	Version   string            `json:"version"`    // "hanko/v0.1"
	SigilID   string            `json:"sigil_id"`   // UUID
	Caps      []CapabilityToken `json:"caps"`       // capability list
	Issuer    string            `json:"issuer"`     // "hanko-broker@obyw.one"
	IssuedAt  time.Time         `json:"issued_at"`  // RFC3339
	ExpiresAt time.Time         `json:"expires_at"` // RFC3339
	Signature []byte            `json:"signature"`  // Ed25519 over canonical JSON body (excl. this field)
}

// RevocationList is an append-only log of revoked Sigils and capability
// tokens distributed to all verifiers. Pull model for v0.1; push (NATS) in
// v0.2 per spec §9 / OQ-3.
type RevocationList struct {
	Entries []RevocationEntry `json:"entries"`
}

// RevocationEntry records a single revoked entity.
type RevocationEntry struct {
	ID         string    `json:"id"`          // UUID of the revoked entity
	TargetType string    `json:"target_type"` // "sigil" | "cap" | "attestation"
	Reason     string    `json:"reason,omitempty"`
	RevokedAt  time.Time `json:"revoked_at"`  // RFC3339
	RevokedBy  string    `json:"revoked_by"`  // UUID of the issuer sigil
}

// SessionType classifies who owns a session for TTL purposes.
type SessionType string

const (
	SessionTypeOperator SessionType = "operator" // 7 days
	SessionTypeCLI      SessionType = "cli"      // 1 hour
	SessionTypeWeb      SessionType = "web"      // 30 minutes
)

// Session is a broker-managed session blob persisted in Valkey (primary)
// and Postgres (audit mirror). The JSON blob carries whatever the broker
// needs for session state — for v0.1 this is the Sigil ID + scope grants.
type Session struct {
	ID        string            `json:"id"`         // UUID
	SigilID   string            `json:"sigil_id"`   // owning Sigil UUID
	Type      SessionType       `json:"type"`       // operator | cli | web
	Payload   map[string]string `json:"payload"`    // opaque key-value blob
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// VerifyError represents a structured denial from the broker.
type VerifyError struct {
	Code    string `json:"code"`             // e.g. "capability_expired"
	Message string `json:"message"`
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Message }

// Sentinel verify errors matching the exit codes in spec §5.
var (
	ErrSignatureInvalid = &VerifyError{Code: "signature_invalid", Message: "attestation signature does not match canonical JSON body"}
	ErrSigilRevoked     = &VerifyError{Code: "sigil_revoked", Message: "sigil has been revoked"}
	ErrCapRevoked       = &VerifyError{Code: "cap_revoked", Message: "capability token has been revoked"}
	ErrCapExpired       = &VerifyError{Code: "capability_expired", Message: "capability token is expired"}
	// ErrNonceReplayed is kept for backwards compatibility; new code uses ErrReplayAttack.
	ErrNonceReplayed = &VerifyError{Code: "nonce_replayed", Message: "capability token nonce has already been used"}
	// ErrReplayAttack is returned by VerifyAttestation when a concurrent or
	// repeated verify call presents a nonce that was already atomically consumed
	// by a prior call (F-4.4). The distinction from ErrNonceReplayed is that
	// ReplayAttack is explicitly race-proof: the atomic ConsumeNonce check
	// guarantees at most one caller sees consumed=true for any given nonce.
	ErrReplayAttack  = &VerifyError{Code: "replay_attack", Message: "nonce already consumed — concurrent or replayed attestation rejected"}
	ErrScopeMismatch = &VerifyError{Code: "scope_mismatch", Message: "capability token scope does not cover the requested action"}
	// ErrScopeUnknown is the NF-4 HARD-REJECT denial: the capability token
	// claims a scope the consumer does not recognize. Consumers MUST reject
	// (HTTP 403) and emit an unknown_scope_rejected audit event — they must
	// NEVER silently accept an unknown scope.
	ErrScopeUnknown = &VerifyError{Code: "unknown_scope_rejected", Message: "capability token scope is not recognized by this consumer"}
)
