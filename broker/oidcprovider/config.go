// Package oidcprovider implements the hanko-broker OIDC provider façade
// (W6.2b — hanko-oidc-provider-facade-2026-07-13).
//
// This turns the broker from a "capability-token issuer" (broker/oidc.go —
// asymmetric ingress: validate external IdP JWTs) into an **OIDC provider**:
// serves a discovery document, an authorization endpoint, a token endpoint,
// and a userinfo endpoint. Minted ID tokens are EdDSA-signed by the SAME
// broker key that already backs /api/v1/jwks — clients (e.g. Mattermost's
// generic OpenID connector) verify against that JWKS.
//
// Scope of this package (per spec W1 + W2):
//   - Static client registry with bcrypt-hashed secrets
//     (unknown client / non-matching redirect_uri → hard reject)
//   - Local user store (username + bcrypt password hash → id_token sub)
//     — brutal-minimal login page; passkeys later
//   - Authorization-code flow only, code TTL 60s, single-use
//     (replay → 400 invalid_grant per AC-06)
//   - PKCE accepted but not required (tailnet-internal confidential clients)
//   - ID token EdDSA/Ed25519 signed by broker signer, `kid` from broker JWKS
//   - Audit JSONL append (mirrors broker/oidc.go pattern) — every
//     authorize/token/userinfo/denied round-trip
//
// Explicitly NOT in this package:
//   - Discovery URL enforcement / TLS (operator topology — Tailscale-only)
//   - go-oidc / Mattermost E2E wiring (ansible role — W3 of the spec)
//   - shi doctor hanko-oidc-provider (shikki-side — separate spec)
//   - Postgres persistence of codes / sessions (in-memory for now — the
//     broker is a single-process systemd unit; process restart flushes
//     transient auth state, which is fine at spec-defined 60s code TTL)
package oidcprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// ClientRow is the static client-registry entry — declared operator-side
// in the provider config JSON (spec NF-2, fail-closed).
type ClientRow struct {
	// ClientID is the public identifier passed by the RP in authorize/token.
	ClientID string `json:"client_id"`
	// ClientSecretHash is a bcrypt hash of the confidential client secret.
	// Generate with: `htpasswd -bnBC 12 "" secret | tr -d ':\n'`.
	ClientSecretHash string `json:"client_secret_hash"`
	// RedirectURIs is the exact-match allow list for the `redirect_uri`
	// authorize parameter and the token-endpoint redirect_uri echo
	// (RFC 6749 §3.1.2.3).
	RedirectURIs []string `json:"redirect_uris"`
	// AllowedScopes bounds the `scope` authorize parameter. Requested
	// scopes are silently dropped if not on this list; the openid scope
	// itself must be present or the flow is not an OIDC flow.
	AllowedScopes []string `json:"allowed_scopes"`
}

// VerifySecret returns nil when secret matches ClientSecretHash. Uses
// bcrypt.CompareHashAndPassword; constant-time comparison lives inside.
func (c ClientRow) VerifySecret(secret string) error {
	if c.ClientSecretHash == "" {
		return errors.New("oidcprovider: client has empty secret hash (misconfigured)")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.ClientSecretHash), []byte(secret)); err != nil {
		return err
	}
	return nil
}

// RedirectAllowed reports whether uri exactly matches one of RedirectURIs.
// No prefix / wildcard tolerance — matches Mattermost / go-oidc expectations
// and follows the same fail-closed posture as the OIDC bootstrap policy check.
func (c ClientRow) RedirectAllowed(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// ScopeAllowed reports whether scope is on the client's allow list.
func (c ClientRow) ScopeAllowed(scope string) bool {
	for _, allowed := range c.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// UserRow is the local identity — declared operator-side. `Sub` becomes
// the id_token `sub` claim; keep it stable across renames (email domain,
// display-name changes) so downstream RPs' account bindings don't break.
type UserRow struct {
	// Sub is the OIDC subject identifier — appears in id_token.sub and
	// userinfo.sub. MUST be stable per RFC 6749 §5.1 "sub".
	Sub string `json:"sub"`
	// Username is the login-page identifier. Case-sensitive exact match.
	Username string `json:"username"`
	// PasswordHash is bcrypt of the user's password. See ClientRow.ClientSecretHash
	// for a generation snippet.
	PasswordHash string `json:"password_hash"`
	// Name is the display name for the OIDC `profile` scope.
	Name string `json:"name,omitempty"`
	// Email is the OIDC `email` scope claim.
	Email string `json:"email,omitempty"`
	// EmailVerified is the OIDC `email_verified` boolean claim.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Enabled=false locks the account without deleting the row (offboarding).
	Enabled bool `json:"enabled"`
}

// VerifyPassword returns nil when password matches PasswordHash.
func (u UserRow) VerifyPassword(password string) error {
	if !u.Enabled {
		return errors.New("oidcprovider: account disabled")
	}
	if u.PasswordHash == "" {
		return errors.New("oidcprovider: user has empty password hash (misconfigured)")
	}
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
}

// ProviderConfig is the JSON file operator-controlled at
// HANKO_OIDCP_CONFIG_PATH. See docs/oidc-provider.md for the schema.
type ProviderConfig struct {
	Clients []ClientRow `json:"clients"`
	Users   []UserRow   `json:"users"`
}

// LoadProviderConfig parses the JSON file at `path`. Missing file → empty
// config (no clients, no users → every authorize/token call rejects; safe
// default, matches broker/oidc.go LoadOIDCPolicy behavior).
func LoadProviderConfig(path string) (*ProviderConfig, error) {
	if path == "" {
		return &ProviderConfig{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ProviderConfig{}, nil
		}
		return nil, fmt.Errorf("oidcprovider: config: %w", err)
	}
	var cfg ProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("oidcprovider: config: parse: %w", err)
	}
	return &cfg, nil
}

// LookupClient returns (row, true) when client_id exists in the registry.
func (c *ProviderConfig) LookupClient(clientID string) (ClientRow, bool) {
	for _, row := range c.Clients {
		if row.ClientID == clientID {
			return row, true
		}
	}
	return ClientRow{}, false
}

// LookupUserByUsername returns (row, true) when username exists AND enabled.
func (c *ProviderConfig) LookupUserByUsername(username string) (UserRow, bool) {
	for _, row := range c.Users {
		if row.Username == username && row.Enabled {
			return row, true
		}
	}
	return UserRow{}, false
}

// LookupUserBySub returns (row, true) when sub exists AND enabled. Used
// by the userinfo endpoint (session cookie carries sub, not username).
func (c *ProviderConfig) LookupUserBySub(sub string) (UserRow, bool) {
	for _, row := range c.Users {
		if row.Sub == sub && row.Enabled {
			return row, true
		}
	}
	return UserRow{}, false
}
