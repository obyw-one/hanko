package oidcprovider_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	"github.com/FJ-Studios/hanko/broker/oidcprovider"
	"github.com/FJ-Studios/hanko/store"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// mustHash returns a bcrypt hash of s, failing the test on error.
func mustHash(t *testing.T, s string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

const testIssuer = "http://100.64.0.2:8788"
const testClientID = "mattermost-chat-obyw"
const testClientSecret = "hunter2-oidc-secret"
const testRedirectURI = "https://chat.obyw.one/signup/openid/complete"
const testUsername = "alice"
const testPassword = "correct-horse-battery"
const testSub = "alice@obyw.one"

type fixture struct {
	t        *testing.T
	srv      *broker.HTTPServer
	prov     *oidcprovider.Provider
	pub      ed25519.PublicKey
	now      time.Time
	audit    string
	registry *oidcprovider.ProviderConfig
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	registry := &oidcprovider.ProviderConfig{
		Clients: []oidcprovider.ClientRow{{
			ClientID:         testClientID,
			ClientSecretHash: mustHash(t, testClientSecret),
			RedirectURIs:     []string{testRedirectURI},
			AllowedScopes:    []string{"openid", "profile", "email"},
		}},
		Users: []oidcprovider.UserRow{{
			Sub:           testSub,
			Username:      testUsername,
			PasswordHash:  mustHash(t, testPassword),
			Name:          "Alice Chen",
			Email:         testSub,
			EmailVerified: true,
			Enabled:       true,
		}},
	}

	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	audit := filepath.Join(t.TempDir(), "audit.jsonl")

	prov, err := oidcprovider.New(oidcprovider.Config{
		Issuer:     testIssuer,
		SignerPriv: priv,
		SignerPub:  pub,
		Registry:   registry,
		AuditPath:  audit,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("oidcprovider.New: %v", err)
	}

	b := broker.New(store.NewMemStore(), pub, priv)
	hs, err := broker.NewHTTPServer(b)
	if err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}
	if err := hs.AttachOIDCProvider(prov); err != nil {
		t.Fatalf("AttachOIDCProvider: %v", err)
	}

	return &fixture{
		t:        t,
		srv:      hs,
		prov:     prov,
		pub:      pub,
		now:      now,
		audit:    audit,
		registry: registry,
	}
}

// serve issues req against the wired mux and returns the recorder.
func (f *fixture) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// authorize sends a GET /authorize with the given optional session cookie.
// Returns the recorder + parsed redirect Location (if any).
func (f *fixture) authorize(sessionCookie string, params url.Values) (*httptest.ResponseRecorder, *url.URL) {
	u := url.URL{Path: "/api/v1/oidc/authorize", RawQuery: params.Encode()}
	req := httptest.NewRequest(http.MethodGet, u.String(), nil)
	if sessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: oidcprovider.SessionCookieName, Value: sessionCookie})
	}
	rec := f.serve(req)
	loc := rec.Header().Get("Location")
	if loc == "" {
		return rec, nil
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		f.t.Fatalf("parse redirect: %v", err)
	}
	return rec, parsed
}

// login sends POST /login with credentials + the full authorize params echoed.
// Returns the recorder + parsed redirect + the session token if the login set one.
func (f *fixture) login(username, password string, params url.Values) (rec *httptest.ResponseRecorder, redirect *url.URL, sessionTok string) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	for k, vs := range params {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oidc/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = f.serve(req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == oidcprovider.SessionCookieName {
			sessionTok = ck.Value
		}
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		parsed, err := url.Parse(loc)
		if err != nil {
			f.t.Fatalf("parse redirect: %v", err)
		}
		redirect = parsed
	}
	return rec, redirect, sessionTok
}

// token sends a POST /token form request.
func (f *fixture) token(form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.serve(req)
}

// standardAuthorizeParams returns the canonical set of authorize query
// parameters used across happy-path tests.
func standardAuthorizeParams() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", testClientID)
	q.Set("redirect_uri", testRedirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", "xyz-state-123")
	q.Set("nonce", "n-0S6_WzA2Mj")
	return q
}

// --- AC-01: discovery -----------------------------------------------------

func TestDiscovery_Serves(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := f.serve(req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	var doc oidcprovider.Discovery
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if doc.Issuer != testIssuer {
		t.Errorf("issuer: got %q want %q", doc.Issuer, testIssuer)
	}
	if doc.AuthorizationEndpoint != testIssuer+"/api/v1/oidc/authorize" {
		t.Errorf("authorization_endpoint: got %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != testIssuer+"/api/v1/oidc/token" {
		t.Errorf("token_endpoint: got %q", doc.TokenEndpoint)
	}
	if doc.JWKSURI != testIssuer+"/api/v1/jwks" {
		t.Errorf("jwks_uri: got %q", doc.JWKSURI)
	}
	if doc.UserinfoEndpoint != testIssuer+"/api/v1/oidc/userinfo" {
		t.Errorf("userinfo_endpoint: got %q", doc.UserinfoEndpoint)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) == 0 ||
		doc.IDTokenSigningAlgValuesSupported[0] != "EdDSA" {
		t.Errorf("id_token_signing_alg_values_supported: got %v want [EdDSA]",
			doc.IDTokenSigningAlgValuesSupported)
	}
	if !containsStr(doc.ResponseTypesSupported, "code") {
		t.Errorf("response_types: want to contain 'code'; got %v", doc.ResponseTypesSupported)
	}
	if !containsStr(doc.ScopesSupported, "openid") {
		t.Errorf("scopes: want to contain 'openid'; got %v", doc.ScopesSupported)
	}
}

// --- AC-02: round-trip code flow → ID token ------------------------------

func TestRoundTrip_CodeFlow(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()

	// 1) GET /authorize with no session → login page.
	rec, redirect := f.authorize("", params)
	if redirect != nil {
		t.Fatalf("unauthenticated authorize should render login page, got redirect to %s", redirect)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("login page status: got %d want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("login page Content-Type: got %q want text/html*", ct)
	}
	if !strings.Contains(rec.Body.String(), "Sign in with hanko") {
		t.Errorf("login page body missing title; body=%s", rec.Body.String())
	}

	// 2) POST /login → 302 to redirect_uri with code + state.
	_, redirect, sessTok := f.login(testUsername, testPassword, params)
	if sessTok == "" {
		t.Fatalf("login did not set session cookie")
	}
	if redirect == nil {
		t.Fatalf("login did not 302")
	}
	if redirect.Host != "chat.obyw.one" || redirect.Path != "/signup/openid/complete" {
		t.Errorf("redirect target: got %s want %s", redirect, testRedirectURI)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", redirect.RawQuery)
	}
	if got := redirect.Query().Get("state"); got != "xyz-state-123" {
		t.Errorf("state echoed: got %q want %q", got, "xyz-state-123")
	}

	// 3) POST /token — exchange code for id_token + access_token.
	tokForm := url.Values{}
	tokForm.Set("grant_type", "authorization_code")
	tokForm.Set("client_id", testClientID)
	tokForm.Set("client_secret", testClientSecret)
	tokForm.Set("code", code)
	tokForm.Set("redirect_uri", testRedirectURI)
	rec = f.token(tokForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token resp: %v; body=%s", err, rec.Body.String())
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type: got %q want Bearer", resp.TokenType)
	}
	if resp.IDToken == "" || resp.AccessToken == "" {
		t.Fatalf("empty tokens; resp=%+v", resp)
	}
	if resp.Scope != "openid profile email" {
		t.Errorf("scope: got %q want 'openid profile email'", resp.Scope)
	}

	// 4) ID token verifies against broker's Ed25519 public key served via
	//    /api/v1/jwks — this is exactly what go-oidc does at the RP side.
	jwksPub := brokerPubFromJWKS(t, f)
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(testIssuer),
		jwt.WithAudience(testClientID),
		jwt.WithTimeFunc(func() time.Time { return f.now }),
	)
	var claims jwt.MapClaims
	_, err := parser.ParseWithClaims(resp.IDToken, &claims, func(t *jwt.Token) (interface{}, error) {
		return jwksPub, nil
	})
	if err != nil {
		t.Fatalf("id_token verify against JWKS pub: %v", err)
	}
	if claims["sub"] != testSub {
		t.Errorf("id_token sub: got %v want %s", claims["sub"], testSub)
	}
	if claims["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("id_token nonce: got %v want %s", claims["nonce"], "n-0S6_WzA2Mj")
	}
	if claims["email"] != testSub {
		t.Errorf("id_token email: got %v want %s", claims["email"], testSub)
	}
	if claims["email_verified"] != true {
		t.Errorf("id_token email_verified: got %v want true", claims["email_verified"])
	}

	// 5) Header kid MUST match the broker's JWKS kid — spec: "sign with
	//    the existing key". Otherwise RPs can't correlate.
	parts := strings.Split(resp.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token: expected 3 segments; got %d", len(parts))
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		t.Fatalf("decode header json: %v", err)
	}
	wantKid := jwksKid(f.pub)
	if hdr["kid"] != wantKid {
		t.Errorf("id_token kid: got %v want %s", hdr["kid"], wantKid)
	}
	if hdr["alg"] != "EdDSA" {
		t.Errorf("id_token alg: got %v want EdDSA", hdr["alg"])
	}

	// 6) Userinfo w/ access token returns matching claims.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	uiRec := f.serve(req)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("userinfo status: got %d want 200; body=%s", uiRec.Code, uiRec.Body.String())
	}
	var ui map[string]any
	if err := json.Unmarshal(uiRec.Body.Bytes(), &ui); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if ui["sub"] != testSub {
		t.Errorf("userinfo sub: got %v want %s", ui["sub"], testSub)
	}
	if ui["name"] != "Alice Chen" {
		t.Errorf("userinfo name: got %v want Alice Chen", ui["name"])
	}
}

// --- AC-04: unknown client / non-registered redirect_uri → 4xx ------------

func TestAuthorize_UnknownClient(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	params.Set("client_id", "not-a-real-client")
	rec, _ := f.authorize("", params)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Errorf("body: want to contain invalid_client; got %s", rec.Body.String())
	}
	assertAuditContains(t, f.audit, `"reason":"unknown_client"`)
}

func TestAuthorize_UnregisteredRedirect(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	params.Set("redirect_uri", "https://evil.example/callback")
	rec, _ := f.authorize("", params)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "redirect_uri not registered") {
		t.Errorf("body: want redirect_uri message; got %s", rec.Body.String())
	}
	assertAuditContains(t, f.audit, `"reason":"redirect_uri_mismatch"`)
}

// --- AC-06: code replay → invalid_grant ----------------------------------

func TestToken_CodeReplay(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	_, redirect, _ := f.login(testUsername, testPassword, params)
	if redirect == nil {
		t.Fatal("no redirect from login")
	}
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)

	// First exchange succeeds.
	rec := f.token(form)
	if rec.Code != http.StatusOK {
		t.Fatalf("first exchange: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Second exchange → 400 invalid_grant.
	rec = f.token(form)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("replay: status got %d want 400", rec.Code)
	}
	var e map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode err resp: %v", err)
	}
	if e["error"] != "invalid_grant" {
		t.Errorf("replay: error got %q want invalid_grant", e["error"])
	}
	assertAuditContains(t, f.audit, `"reason":"invalid_or_replayed_code"`)
}

// --- token endpoint auth failures ----------------------------------------

func TestToken_BadClientSecret(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	_, redirect, _ := f.login(testUsername, testPassword, params)
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", testClientID)
	form.Set("client_secret", "wrong-secret")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)

	rec := f.token(form)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", rec.Code)
	}
	var e map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e["error"] != "invalid_client" {
		t.Errorf("error: got %q want invalid_client", e["error"])
	}
}

func TestToken_UnknownClient(t *testing.T) {
	f := newFixture(t)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "not-a-client")
	form.Set("client_secret", "anything")
	form.Set("code", "some-code")
	form.Set("redirect_uri", testRedirectURI)

	rec := f.token(form)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", rec.Code)
	}
}

func TestToken_UnsupportedGrant(t *testing.T) {
	f := newFixture(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)

	rec := f.token(form)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	var e map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e["error"] != "unsupported_grant_type" {
		t.Errorf("error: got %q want unsupported_grant_type", e["error"])
	}
}

// --- code binding checks -------------------------------------------------

func TestToken_CodeIssuedToDifferentClient(t *testing.T) {
	f := newFixture(t)
	// Add a second client so we can attempt cross-client code use.
	f.registry.Clients = append(f.registry.Clients, oidcprovider.ClientRow{
		ClientID:         "second-client",
		ClientSecretHash: mustHash(t, "s2-secret"),
		RedirectURIs:     []string{testRedirectURI},
		AllowedScopes:    []string{"openid"},
	})
	f.prov.Reload(f.registry)

	params := standardAuthorizeParams()
	_, redirect, _ := f.login(testUsername, testPassword, params)
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "second-client")
	form.Set("client_secret", "s2-secret")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)

	rec := f.token(form)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	var e map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e["error"] != "invalid_grant" {
		t.Errorf("error: got %q want invalid_grant", e["error"])
	}
}

func TestToken_RedirectURIMismatch(t *testing.T) {
	f := newFixture(t)
	// Add second redirect_uri so it's in the registry but wasn't used at
	// authorize time — trips the token-time exact-match check.
	f.registry.Clients[0].RedirectURIs = append(
		f.registry.Clients[0].RedirectURIs,
		"https://chat.obyw.one/alt/openid/complete",
	)
	f.prov.Reload(f.registry)

	params := standardAuthorizeParams()
	_, redirect, _ := f.login(testUsername, testPassword, params)
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", "https://chat.obyw.one/alt/openid/complete")

	rec := f.token(form)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
}

// --- PKCE ---------------------------------------------------------------

func TestToken_PKCE_HappyPath(t *testing.T) {
	f := newFixture(t)
	verifier := "s3cret-verifier-with-enough-length-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	params := standardAuthorizeParams()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	_, redirect, _ := f.login(testUsername, testPassword, params)
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("code_verifier", verifier)

	rec := f.token(form)
	if rec.Code != http.StatusOK {
		t.Errorf("PKCE happy: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestToken_PKCE_WrongVerifier(t *testing.T) {
	f := newFixture(t)
	verifier := "s3cret-verifier-with-enough-length-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	params := standardAuthorizeParams()
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	_, redirect, _ := f.login(testUsername, testPassword, params)
	code := redirect.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", testRedirectURI)
	form.Set("code_verifier", "totally-different-verifier")

	rec := f.token(form)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
}

// --- login: wrong credentials → re-render login page ----------------------

func TestLogin_WrongPassword(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	rec, redirect, sessTok := f.login(testUsername, "wrong-password", params)
	if redirect != nil {
		t.Errorf("wrong password should not redirect; got %s", redirect)
	}
	if sessTok != "" {
		t.Errorf("wrong password should not set session cookie")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("re-render status: got %d want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Errorf("re-render body missing error banner; got: %s", rec.Body.String())
	}
	assertAuditContains(t, f.audit, `"reason":"invalid_credentials"`)
}

// --- authorize: session cookie → no login page ---------------------------

func TestAuthorize_ExistingSession_ImmediateRedirect(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()

	// First, log in to establish a session.
	_, _, sessTok := f.login(testUsername, testPassword, params)
	if sessTok == "" {
		t.Fatal("no session token from first login")
	}

	// Second /authorize with the session cookie → 302 straight through.
	rec, redirect := f.authorize(sessTok, params)
	if rec.Code != http.StatusFound {
		t.Errorf("status: got %d want 302", rec.Code)
	}
	if redirect == nil || redirect.Query().Get("code") == "" {
		t.Errorf("expected redirect with code; got %v", redirect)
	}
}

// --- userinfo failures --------------------------------------------------

func TestUserinfo_MissingBearer(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	rec := f.serve(req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", rec.Code)
	}
}

func TestUserinfo_BadToken(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	rec := f.serve(req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "invalid_token") {
		t.Errorf("WWW-Authenticate: got %q want invalid_token", got)
	}
}

// --- scope: openid missing --------------------------------------------------

func TestAuthorize_NoOpenidScope(t *testing.T) {
	f := newFixture(t)
	params := standardAuthorizeParams()
	params.Set("scope", "profile email")
	rec, redirect := f.authorize("", params)
	if rec.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302; body=%s", rec.Code, rec.Body.String())
	}
	if redirect == nil {
		t.Fatal("expected error redirect")
	}
	if redirect.Query().Get("error") != "invalid_scope" {
		t.Errorf("error: got %q want invalid_scope", redirect.Query().Get("error"))
	}
	if redirect.Query().Get("state") != "xyz-state-123" {
		t.Errorf("state echoed: got %q", redirect.Query().Get("state"))
	}
}

// --- discovery method check --------------------------------------------

func TestDiscovery_MethodNotAllowed(t *testing.T) {
	f := newFixture(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/.well-known/openid-configuration", nil)
		rec := f.serve(req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d want 405", m, rec.Code)
		}
	}
}

// --- New() input validation --------------------------------------------

func TestNew_Validation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg := &oidcprovider.ProviderConfig{}
	cases := []struct {
		name string
		cfg  oidcprovider.Config
	}{
		{"empty issuer", oidcprovider.Config{SignerPriv: priv, SignerPub: pub, Registry: reg}},
		{"trailing slash issuer", oidcprovider.Config{Issuer: "http://x/", SignerPriv: priv, SignerPub: pub, Registry: reg}},
		{"missing signer priv", oidcprovider.Config{Issuer: "http://x", SignerPub: pub, Registry: reg}},
		{"missing signer pub", oidcprovider.Config{Issuer: "http://x", SignerPriv: priv, Registry: reg}},
		{"nil registry", oidcprovider.Config{Issuer: "http://x", SignerPriv: priv, SignerPub: pub}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := oidcprovider.New(tc.cfg); err == nil {
				t.Errorf("want error, got nil")
			}
		})
	}
}

// --- config loading -----------------------------------------------------

func TestLoadProviderConfig_Empty(t *testing.T) {
	cfg, err := oidcprovider.LoadProviderConfig("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if len(cfg.Clients) != 0 || len(cfg.Users) != 0 {
		t.Errorf("empty cfg: got %d clients / %d users", len(cfg.Clients), len(cfg.Users))
	}
}

func TestLoadProviderConfig_MissingFile(t *testing.T) {
	cfg, err := oidcprovider.LoadProviderConfig("/tmp/hanko-does-not-exist-" + fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if len(cfg.Clients) != 0 {
		t.Errorf("missing cfg: want empty; got %d clients", len(cfg.Clients))
	}
}

func TestLoadProviderConfig_ParsesFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	content := `{
  "clients": [
    {"client_id":"c1","client_secret_hash":"$2a$10$abc","redirect_uris":["http://x"],"allowed_scopes":["openid"]}
  ],
  "users": [
    {"sub":"u1","username":"user1","password_hash":"$2a$10$xyz","enabled":true}
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := oidcprovider.LoadProviderConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].ClientID != "c1" {
		t.Errorf("clients: %+v", cfg.Clients)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Sub != "u1" {
		t.Errorf("users: %+v", cfg.Users)
	}
}

// --- helpers ---------------------------------------------------------

// jwksKid mirrors broker.brokerKid — base64url(sha256(pub)). Kept local
// here so the test file does not need access to the broker package's
// unexported helper.
func jwksKid(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// brokerPubFromJWKS decodes the Ed25519 public key from the /api/v1/jwks
// endpoint served by the fixture — exercises the RP verification path.
func brokerPubFromJWKS(t *testing.T, f *fixture) ed25519.PublicKey {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jwks", nil)
	rec := f.serve(req)
	var doc struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	return ed25519.PublicKey(xBytes)
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func assertAuditContains(t *testing.T, path, needle string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit %s: %v", path, err)
	}
	if !strings.Contains(string(raw), needle) {
		t.Errorf("audit file missing %q; content=%s", needle, string(raw))
	}
}
