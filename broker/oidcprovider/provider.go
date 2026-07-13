package oidcprovider

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenTTL is the lifetime of the access token returned by /token.
// Kept modest — RPs re-authenticate on session refresh.
const AccessTokenTTL = 10 * time.Minute

// IDTokenTTL is the lifetime of the id_token — go-oidc treats id_token
// expiry as session freshness for downstream RPs.
const IDTokenTTL = 10 * time.Minute

// AuditOutcome tags every audited event (JSONL line) so shikki-side
// bridges can map to NATS `shikki.<ws>.broker.hanko.oidc.<action>.<corr>`
// via the OIDCSubject factory (spec AC-07 — no shikki.* literal in this repo).
type AuditOutcome string

const (
	OutcomeAuthRequest    AuditOutcome = "auth_request"
	OutcomeCodeIssued     AuditOutcome = "code_issued"
	OutcomeTokenIssued    AuditOutcome = "token_issued"
	OutcomeTokenFailed    AuditOutcome = "token_failed"
	OutcomeUserinfoServed AuditOutcome = "userinfo_served"
	OutcomeUserinfoFailed AuditOutcome = "userinfo_failed"
	OutcomeFailed         AuditOutcome = "failed"
	OutcomeSessionRevoked AuditOutcome = "session_revoked"
)

// Config is the runtime configuration for a Provider.
type Config struct {
	// Issuer is the base URL that appears in the discovery `issuer` field
	// and every id_token/access_token `iss` claim. MUST match the
	// authority the RP is configured with (spec: http://100.64.0.2:8788).
	Issuer string

	// SignerPriv is the Ed25519 private key that signs id_tokens and
	// access_tokens. MUST be the same key backing /api/v1/jwks so the
	// RP's JWKS-based verification succeeds.
	SignerPriv ed25519.PrivateKey

	// SignerPub is the corresponding public key. Used to compute the JWKS
	// kid the tokens are stamped with.
	SignerPub ed25519.PublicKey

	// Registry provides clients + users. Passed by pointer so operator
	// hot-reload (SIGHUP, etc.) can atomically swap the pointer without
	// restarting the process (Provider.Reload).
	Registry *ProviderConfig

	// AuditPath, when non-empty, is a JSONL file every audit row is
	// appended to. Same posture as broker/oidc.go audit — best-effort,
	// never fails the request.
	AuditPath string

	// CookieSecure controls the Secure attribute on the hanko_session
	// cookie. Set false only in tests / plain-http Tailscale deployments.
	CookieSecure bool

	// Now is time.Now unless overridden by tests.
	Now func() time.Time

	// CodeTTL / SessionTTL override the defaults for tests. Zero → default.
	CodeTTL    time.Duration
	SessionTTL time.Duration
}

// Provider is the in-process OIDC provider façade.
type Provider struct {
	cfg      Config
	registry *ProviderConfig
	registryMu sync.RWMutex

	kid string

	codes    *codeStore
	sessions *sessionStore

	auditMu sync.Mutex
}

// New wires a Provider from cfg. Fails on missing signer / issuer / registry.
func New(cfg Config) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidcprovider: New: Issuer must not be empty")
	}
	if strings.HasSuffix(cfg.Issuer, "/") {
		return nil, errors.New("oidcprovider: New: Issuer must NOT have a trailing slash (RFC 8414 §2)")
	}
	if len(cfg.SignerPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("oidcprovider: New: SignerPriv missing or wrong size")
	}
	if len(cfg.SignerPub) != ed25519.PublicKeySize {
		return nil, errors.New("oidcprovider: New: SignerPub missing or wrong size")
	}
	if cfg.Registry == nil {
		return nil, errors.New("oidcprovider: New: Registry must not be nil")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	sum := sha256.Sum256(cfg.SignerPub)
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	return &Provider{
		cfg:      cfg,
		registry: cfg.Registry,
		kid:      kid,
		codes:    newCodeStore(cfg.Now, cfg.CodeTTL),
		sessions: newSessionStore(cfg.Now, cfg.SessionTTL),
	}, nil
}

// Reload atomically swaps the registry (client + user rows). Called by
// operator hot-reload wiring; safe under live traffic.
func (p *Provider) Reload(cfg *ProviderConfig) {
	if cfg == nil {
		return
	}
	p.registryMu.Lock()
	p.registry = cfg
	p.registryMu.Unlock()
}

// snapshot returns the current registry under a read lock. Cheap.
func (p *Provider) snapshot() *ProviderConfig {
	p.registryMu.RLock()
	defer p.registryMu.RUnlock()
	return p.registry
}

// Kid is the JWKS key id the provider stamps its tokens with — the same
// kid the broker's /api/v1/jwks returns. Exported for testing / doctor.
func (p *Provider) Kid() string { return p.kid }

// --- HTTP routes -----------------------------------------------------------

// Discovery is the JSON shape returned by /.well-known/openid-configuration.
// Field set is the RFC 8414 §2 minimum for go-oidc / Mattermost.
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// HandleDiscovery serves /.well-known/openid-configuration.
func (p *Provider) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc := Discovery{
		Issuer:                            p.cfg.Issuer,
		AuthorizationEndpoint:             p.cfg.Issuer + "/api/v1/oidc/authorize",
		TokenEndpoint:                     p.cfg.Issuer + "/api/v1/oidc/token",
		UserinfoEndpoint:                  p.cfg.Issuer + "/api/v1/oidc/userinfo",
		JWKSURI:                           p.cfg.Issuer + "/api/v1/jwks",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"EdDSA"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "email_verified"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// authorizeParams is the parsed shape of the authorize query.
type authorizeParams struct {
	responseType        string
	clientID            string
	redirectURI         string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

func parseAuthorize(r *http.Request) authorizeParams {
	q := r.URL.Query()
	return authorizeParams{
		responseType:        q.Get("response_type"),
		clientID:            q.Get("client_id"),
		redirectURI:         q.Get("redirect_uri"),
		scope:               q.Get("scope"),
		state:               q.Get("state"),
		nonce:               q.Get("nonce"),
		codeChallenge:       q.Get("code_challenge"),
		codeChallengeMethod: q.Get("code_challenge_method"),
	}
}

// HandleAuthorize implements /api/v1/oidc/authorize.
//
// Behavior:
//  1. Validate client_id + redirect_uri BEFORE any redirect (per RFC 6749
//     §4.1.2.1 — invalid redirect_uri MUST NOT redirect back). Bad client
//     or redirect → 400 + audit "failed". This is AC-04.
//  2. Validate response_type / scope. Bad → redirect to redirect_uri with
//     `error=invalid_request` (safe, redirect_uri is now known-good).
//  3. Session cookie present + live → mint code + redirect with code + state.
//  4. No session → render minimal login page. The login POST re-runs the
//     authorize check with a fresh session cookie set.
func (p *Provider) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	params := parseAuthorize(r)
	reg := p.snapshot()

	client, ok := reg.LookupClient(params.clientID)
	if !ok {
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "unknown_client")
		http.Error(w, "invalid_client: unknown client_id", http.StatusBadRequest)
		return
	}
	if params.redirectURI == "" || !client.RedirectAllowed(params.redirectURI) {
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "redirect_uri_mismatch")
		http.Error(w, "invalid_request: redirect_uri not registered", http.StatusBadRequest)
		return
	}
	if params.responseType != "code" {
		errorRedirect(w, r, params.redirectURI, params.state, "unsupported_response_type", "response_type must be 'code'")
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "unsupported_response_type")
		return
	}

	requestedScopes := strings.Fields(params.scope)
	if !containsScope(requestedScopes, "openid") {
		errorRedirect(w, r, params.redirectURI, params.state, "invalid_scope", "openid scope required")
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "no_openid_scope")
		return
	}
	filtered := filterScopes(requestedScopes, client)
	scope := strings.Join(filtered, " ")

	p.audit(OutcomeAuthRequest, params.clientID, "", scope, "")

	// Session cookie check.
	if sub, ok := p.sessionFromRequest(r); ok {
		p.issueCodeAndRedirect(w, r, params, scope, sub)
		return
	}

	// No session → render minimal login page.
	p.renderLoginPage(w, params, scope, "")
}

// HandleLogin implements POST /api/v1/oidc/login — the form target of the
// minimal login page. Validates credentials against the user store, sets
// the session cookie, and issues the code (or re-renders the login page
// with an error banner).
func (p *Provider) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request: cannot parse form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	params := authorizeParams{
		responseType:        r.FormValue("response_type"),
		clientID:            r.FormValue("client_id"),
		redirectURI:         r.FormValue("redirect_uri"),
		scope:               r.FormValue("scope"),
		state:               r.FormValue("state"),
		nonce:               r.FormValue("nonce"),
		codeChallenge:       r.FormValue("code_challenge"),
		codeChallengeMethod: r.FormValue("code_challenge_method"),
	}
	reg := p.snapshot()

	// Re-validate client + redirect_uri (defense in depth — never trust
	// the form values without checking the registry).
	client, ok := reg.LookupClient(params.clientID)
	if !ok {
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "unknown_client")
		http.Error(w, "invalid_client: unknown client_id", http.StatusBadRequest)
		return
	}
	if params.redirectURI == "" || !client.RedirectAllowed(params.redirectURI) {
		p.audit(OutcomeFailed, params.clientID, "", params.scope, "redirect_uri_mismatch")
		http.Error(w, "invalid_request: redirect_uri not registered", http.StatusBadRequest)
		return
	}

	user, ok := reg.LookupUserByUsername(username)
	if !ok || user.VerifyPassword(password) != nil {
		p.audit(OutcomeFailed, params.clientID, username, params.scope, "invalid_credentials")
		p.renderLoginPage(w, params, params.scope, "Invalid username or password.")
		return
	}

	tok, expiresAt, err := p.sessions.create(user.Sub)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    tok,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   p.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	p.issueCodeAndRedirect(w, r, params, params.scope, user.Sub)
}

// issueCodeAndRedirect mints an auth code and 302-redirects the browser
// to redirect_uri with (code, state) query params.
func (p *Provider) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, params authorizeParams, scope, sub string) {
	code, err := p.codes.mint(
		params.clientID,
		params.redirectURI,
		sub,
		scope,
		params.nonce,
		params.codeChallenge,
		params.codeChallengeMethod,
	)
	if err != nil {
		http.Error(w, "server_error: mint code", http.StatusInternalServerError)
		return
	}
	p.audit(OutcomeCodeIssued, params.clientID, sub, scope, "")

	u, err := url.Parse(params.redirectURI)
	if err != nil {
		http.Error(w, "invalid_request: unparseable redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if params.state != "" {
		q.Set("state", params.state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func errorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid_request: unparseable redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// HandleToken implements POST /api/v1/oidc/token — RFC 6749 §4.1.3
// authorization_code grant.
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		p.audit(OutcomeTokenFailed, r.FormValue("client_id"), "", "", "unsupported_grant_type")
		writeTokenErr(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code supported")
		return
	}

	clientID, clientSecret, ok := clientCreds(r)
	if !ok {
		p.audit(OutcomeTokenFailed, clientID, "", "", "missing_client_credentials")
		writeTokenErr(w, http.StatusUnauthorized, "invalid_client", "client credentials missing")
		return
	}

	reg := p.snapshot()
	client, ok := reg.LookupClient(clientID)
	if !ok {
		p.audit(OutcomeTokenFailed, clientID, "", "", "unknown_client")
		writeTokenErr(w, http.StatusUnauthorized, "invalid_client", "unknown client_id")
		return
	}
	if err := client.VerifySecret(clientSecret); err != nil {
		p.audit(OutcomeTokenFailed, clientID, "", "", "client_secret_mismatch")
		writeTokenErr(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	row, ok := p.codes.consume(code)
	if !ok {
		p.audit(OutcomeTokenFailed, clientID, "", "", "invalid_or_replayed_code")
		writeTokenErr(w, http.StatusBadRequest, "invalid_grant", "code unknown, expired, or already used")
		return
	}
	if row.clientID != clientID {
		p.audit(OutcomeTokenFailed, clientID, row.sub, row.scope, "client_id_mismatch")
		writeTokenErr(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if row.redirectURI != redirectURI {
		p.audit(OutcomeTokenFailed, clientID, row.sub, row.scope, "redirect_uri_mismatch")
		writeTokenErr(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorize request")
		return
	}
	if row.codeChallenge != "" {
		if !verifyPKCE(row.codeChallenge, row.codeChallengeMethod, codeVerifier) {
			p.audit(OutcomeTokenFailed, clientID, row.sub, row.scope, "pkce_failed")
			writeTokenErr(w, http.StatusBadRequest, "invalid_grant", "PKCE code_verifier failed")
			return
		}
	}

	user, ok := reg.LookupUserBySub(row.sub)
	if !ok {
		p.audit(OutcomeTokenFailed, clientID, row.sub, row.scope, "user_gone")
		writeTokenErr(w, http.StatusBadRequest, "invalid_grant", "user no longer available")
		return
	}

	now := p.cfg.Now()
	idToken, err := p.signIDToken(user, clientID, row.scope, row.nonce, now)
	if err != nil {
		writeTokenErr(w, http.StatusInternalServerError, "server_error", "sign id_token: "+err.Error())
		return
	}
	accessToken, err := p.signAccessToken(user, clientID, row.scope, now)
	if err != nil {
		writeTokenErr(w, http.StatusInternalServerError, "server_error", "sign access_token: "+err.Error())
		return
	}

	p.audit(OutcomeTokenIssued, clientID, user.Sub, row.scope, "")

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(AccessTokenTTL.Seconds()),
		"id_token":     idToken,
		"scope":        row.scope,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleUserInfo implements GET /api/v1/oidc/userinfo (RFC 6749 §5.3).
// Verifies the Bearer access token signature/expiry and returns claims
// filtered by the token's scope.
func (p *Provider) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		p.audit(OutcomeUserinfoFailed, "", "", "", "missing_bearer")
		http.Error(w, `Bearer realm="hanko"`, http.StatusUnauthorized)
		return
	}
	tok := strings.TrimPrefix(auth, "Bearer ")

	claims, err := p.verifyAccessToken(tok)
	if err != nil {
		p.audit(OutcomeUserinfoFailed, "", "", "", "invalid_token: "+err.Error())
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)

	reg := p.snapshot()
	user, ok := reg.LookupUserBySub(sub)
	if !ok {
		p.audit(OutcomeUserinfoFailed, "", sub, scope, "user_gone")
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}

	body := map[string]any{"sub": user.Sub}
	if containsScope(strings.Fields(scope), "profile") && user.Name != "" {
		body["name"] = user.Name
	}
	if containsScope(strings.Fields(scope), "email") && user.Email != "" {
		body["email"] = user.Email
		body["email_verified"] = user.EmailVerified
	}

	p.audit(OutcomeUserinfoServed, "", sub, scope, "")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// --- token minting ---------------------------------------------------------

func (p *Provider) signIDToken(user UserRow, clientID, scope, nonce string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": p.cfg.Issuer,
		"sub": user.Sub,
		"aud": clientID,
		"exp": now.Add(IDTokenTTL).Unix(),
		"iat": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if containsScope(strings.Fields(scope), "profile") && user.Name != "" {
		claims["name"] = user.Name
	}
	if containsScope(strings.Fields(scope), "email") && user.Email != "" {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = p.kid
	return tok.SignedString(p.cfg.SignerPriv)
}

func (p *Provider) signAccessToken(user UserRow, clientID, scope string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss":       p.cfg.Issuer,
		"sub":       user.Sub,
		"aud":       clientID,
		"exp":       now.Add(AccessTokenTTL).Unix(),
		"iat":       now.Unix(),
		"scope":     scope,
		"token_use": "access",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = p.kid
	return tok.SignedString(p.cfg.SignerPriv)
}

// verifyAccessToken parses a Bearer access token, verifies its signature
// against the broker's Ed25519 public key, and enforces exp/iss. Returns
// the claims map on success.
func (p *Provider) verifyAccessToken(tok string) (jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(p.cfg.Issuer),
		jwt.WithTimeFunc(p.cfg.Now),
	)
	var claims jwt.MapClaims
	_, err := parser.ParseWithClaims(tok, &claims, func(t *jwt.Token) (interface{}, error) {
		return p.cfg.SignerPub, nil
	})
	if err != nil {
		return nil, err
	}
	if use, _ := claims["token_use"].(string); use != "access" {
		return nil, errors.New("token_use is not 'access'")
	}
	return claims, nil
}

// --- helpers ---------------------------------------------------------------

// sessionFromRequest looks up the sub bound to the request's session cookie.
func (p *Provider) sessionFromRequest(r *http.Request) (string, bool) {
	ck, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", false
	}
	return p.sessions.lookup(ck.Value)
}

// clientCreds extracts (client_id, client_secret) from either HTTP Basic
// (client_secret_basic per RFC 6749 §2.3.1) or form body (client_secret_post).
func clientCreds(r *http.Request) (id, secret string, ok bool) {
	if u, p, hasBasic := r.BasicAuth(); hasBasic {
		return u, p, u != ""
	}
	id = r.FormValue("client_id")
	secret = r.FormValue("client_secret")
	return id, secret, id != ""
}

// verifyPKCE returns true iff codeVerifier hashed under `method` equals
// codeChallenge. S256 only; plain rejected (spec: PKCE accepted but not
// required — when present must be strong).
func verifyPKCE(codeChallenge, method, codeVerifier string) bool {
	if codeVerifier == "" {
		return false
	}
	if method == "" {
		method = "plain" // treat missing method as plain; we then reject
	}
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return got == codeChallenge
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// filterScopes drops requested scopes that are neither on the client's
// AllowedScopes list nor a well-known standard scope the provider natively
// serves (openid/profile/email).
func filterScopes(requested []string, client ClientRow) []string {
	out := make([]string, 0, len(requested))
	standard := map[string]struct{}{"openid": {}, "profile": {}, "email": {}}
	for _, s := range requested {
		if _, ok := standard[s]; ok {
			out = append(out, s)
			continue
		}
		if client.ScopeAllowed(s) {
			out = append(out, s)
		}
	}
	return out
}

// --- audit -----------------------------------------------------------------

// audit appends one JSONL line to AuditPath, best-effort. Every request
// touchpoint calls audit(); shikki-side bridges can map outcome → NATS
// subject via the OIDCSubject() factory (spec AC-07 — subject strings live
// in shikki, never here).
func (p *Provider) audit(outcome AuditOutcome, clientID, sub, scope, reason string) {
	if p.cfg.AuditPath == "" {
		return
	}
	row := map[string]any{
		"ts":        p.cfg.Now().UTC().Format(time.RFC3339Nano),
		"outcome":   string(outcome),
		"client_id": clientID,
		"sub":       sub,
		"scope":     scope,
		"reason":    reason,
	}
	line, _ := json.Marshal(row)
	p.auditMu.Lock()
	defer p.auditMu.Unlock()
	f, err := os.OpenFile(p.cfg.AuditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "oidcprovider: audit append failed: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func writeTokenErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// --- login page ------------------------------------------------------------

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>hanko — sign in</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; color: #111; }
h1 { font-size: 1.25rem; margin-bottom: 0.25rem; }
p.sub { color: #555; margin-top: 0; font-size: 0.9rem; }
label { display: block; margin-top: 1rem; font-size: 0.85rem; }
input { width: 100%; padding: 0.5rem; font-size: 1rem; border: 1px solid #999; border-radius: 4px; box-sizing: border-box; }
button { margin-top: 1.25rem; width: 100%; padding: 0.6rem; font-size: 1rem; background: #111; color: #fff; border: 0; border-radius: 4px; cursor: pointer; }
.err { color: #b00020; margin-top: 1rem; font-size: 0.9rem; }
.foot { margin-top: 2rem; color: #888; font-size: 0.75rem; }
</style>
</head>
<body>
<h1>Sign in with hanko</h1>
<p class="sub">to continue to <strong>{{.ClientID}}</strong></p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="POST" action="/api/v1/oidc/login" autocomplete="off">
  <label>Username<input name="username" required autofocus/></label>
  <label>Password<input name="password" type="password" required/></label>
  <input type="hidden" name="response_type" value="{{.ResponseType}}"/>
  <input type="hidden" name="client_id" value="{{.ClientID}}"/>
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"/>
  <input type="hidden" name="scope" value="{{.Scope}}"/>
  <input type="hidden" name="state" value="{{.State}}"/>
  <input type="hidden" name="nonce" value="{{.Nonce}}"/>
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}"/>
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}"/>
  <button type="submit">Sign in</button>
</form>
<p class="foot">hanko-broker · OIDC provider façade · Tailscale-only</p>
</body>
</html>
`))

type loginView struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

func (p *Provider) renderLoginPage(w http.ResponseWriter, params authorizeParams, scope, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	view := loginView{
		ResponseType:        params.responseType,
		ClientID:            params.clientID,
		RedirectURI:         params.redirectURI,
		Scope:               scope,
		State:               params.state,
		Nonce:               params.nonce,
		CodeChallenge:       params.codeChallenge,
		CodeChallengeMethod: params.codeChallengeMethod,
		Error:               errMsg,
	}
	_ = loginTmpl.Execute(w, view)
}

// DrainBody is a small helper used by tests that want to discard a
// response body without inspecting it.
func DrainBody(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
}
