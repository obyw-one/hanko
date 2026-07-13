// Command hanko-broker is the Hanko v0.1 reference CLI.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
// It is NOT related to the teamhanko/hanko project. See README.md §Provenance.
//
// Build:  go build -o hanko-broker ./cmd/hanko-broker
// Usage:  hanko-broker [command] [flags]
//
// Store selection (global flag --store):
//
//	--store mem   in-memory store (demo/test; default when HANKO_PG_DSN is unset)
//	--store pg    Postgres store (default when HANKO_PG_DSN is set)
//
// Broker private key: ~/.hanko/broker.key (hex-encoded Ed25519 private key).
// Generate with: hanko-broker keygen
//
// TODO(shi-hanko-plugin W2): replace HANKO_PG_DSN raw DSN with
// shi-secret://hanko/pg-dsn integration once nuc-dev secrets broker is live.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Parse global --store flag before dispatching.
	args, storeFlag := extractStoreFlag(os.Args[1:])
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "demo":
		runDemo()
	case "keygen":
		runKeygen(args[1:])
	case "status":
		fmt.Println(`{"status":"ok","version":"` + protocol.Version + `","impl":"go-reference"}`)
	case "issue":
		mustArgs(args, 2, "issue requires a sub-command: sigil | cap | attestation")
		runIssue(args[1:], storeFlag)
	case "verify":
		runVerify(args[1:], storeFlag)
	case "revoke":
		mustArgs(args, 2, "revoke requires a sub-command: sigil | cap")
		runRevoke(args[1:], storeFlag)
	case "list":
		mustArgs(args, 2, "list requires a sub-command: sigils")
		runList(args[1:], storeFlag)
	case "serve":
		runServe(args[1:], storeFlag)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

// --- store setup ---

// openStore builds the appropriate Store based on --store flag and env.
// Returns a StoreCloser; caller must defer sc.Close().
func openStore(flag string) store.StoreCloser {
	want := flag
	if want == "" {
		if os.Getenv("HANKO_PG_DSN") != "" {
			want = "pg"
		} else {
			want = "mem"
		}
	}
	switch want {
	case "mem":
		return store.NewMemStoreCloser()
	case "pg":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ps, err := store.NewPgStore(ctx, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot open Postgres store: %v\n", err)
			os.Exit(1)
		}
		return ps
	default:
		fmt.Fprintf(os.Stderr, "error: unknown --store value %q (want: mem | pg)\n", want)
		os.Exit(1)
	}
	panic("unreachable")
}

// loadBrokerKey reads the hex-encoded Ed25519 private key from ~/.hanko/broker.key
// (or the path in HANKO_BROKER_KEY_PATH env var).
func loadBrokerKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	path := os.Getenv("HANKO_BROKER_KEY_PATH")
	if path == "" {
		path = defaultKeyPath()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read broker key from %s: %v\n", path, err)
		fmt.Fprintln(os.Stderr, "  generate with: hanko-broker keygen")
		os.Exit(1)
	}
	privBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "error: broker key at %s is not a valid Ed25519 private key\n", path)
		os.Exit(1)
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// --- issue commands ---

func runIssue(args []string, storeFlag string) {
	if len(args) == 0 {
		die("issue requires a sub-command: sigil | cap | attestation")
	}
	switch args[0] {
	case "sigil":
		runIssueSigil(args[1:], storeFlag)
	case "cap":
		runIssueCap(args[1:], storeFlag)
	case "attestation":
		runIssueAttestation(args[1:], storeFlag)
	default:
		die("unknown issue sub-command %q — want: sigil | cap | attestation", args[0])
	}
}

// issue sigil --subject <id> --pubkey <hex> [--meta key=value ...]
func runIssueSigil(args []string, storeFlag string) {
	var subject, pubkeyHex string
	meta := map[string]string{}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--subject":
			subject = nextArg(args, &i, "--subject")
		case "--pubkey":
			pubkeyHex = nextArg(args, &i, "--pubkey")
		case "--meta":
			kv := nextArg(args, &i, "--meta")
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				die("--meta value must be key=value, got %q", kv)
			}
			meta[parts[0]] = parts[1]
		}
	}
	if subject == "" {
		die("--subject is required")
	}
	if pubkeyHex == "" {
		die("--pubkey is required")
	}
	pubBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		die("--pubkey must be 32-byte hex-encoded Ed25519 public key")
	}

	sc := openStore(storeFlag)
	defer sc.Close()
	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)

	sigil, err := b.IssueSigil(subject, ed25519.PublicKey(pubBytes), nil, meta)
	if err != nil {
		die("IssueSigil: %v", err)
	}
	printJSON(sigil)
}

// issue cap --sigil <id> --scope <s> --ttl <dur>
func runIssueCap(args []string, storeFlag string) {
	var sigilID, scope, ttlStr string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sigil":
			sigilID = nextArg(args, &i, "--sigil")
		case "--scope":
			scope = nextArg(args, &i, "--scope")
		case "--ttl":
			ttlStr = nextArg(args, &i, "--ttl")
		}
	}
	if sigilID == "" {
		die("--sigil is required")
	}
	if scope == "" {
		die("--scope is required")
	}
	if ttlStr == "" {
		die("--ttl is required (e.g. 1h, 30m, 24h)")
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		die("invalid --ttl %q: %v", ttlStr, err)
	}

	sc := openStore(storeFlag)
	defer sc.Close()
	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)

	cap, err := b.IssueCap(sigilID, scope, time.Now().Add(ttl))
	if err != nil {
		die("IssueCap: %v", err)
	}
	printJSON(cap)
}

// issue attestation --sigil <id> --cap <id> [--cap <id> ...] --ttl <dur>
func runIssueAttestation(args []string, storeFlag string) {
	var sigilID, ttlStr string
	var capIDs []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sigil":
			sigilID = nextArg(args, &i, "--sigil")
		case "--cap":
			capIDs = append(capIDs, nextArg(args, &i, "--cap"))
		case "--ttl":
			ttlStr = nextArg(args, &i, "--ttl")
		}
	}
	if sigilID == "" {
		die("--sigil is required")
	}
	if ttlStr == "" {
		die("--ttl is required")
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		die("invalid --ttl %q: %v", ttlStr, err)
	}

	sc := openStore(storeFlag)
	defer sc.Close()
	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)

	// Resolve each cap ID from the store.
	caps := make([]protocol.CapabilityToken, 0, len(capIDs))
	for _, cid := range capIDs {
		c, err := sc.GetCap(cid)
		if err != nil {
			die("cap %s not found: %v", cid, err)
		}
		caps = append(caps, *c)
	}

	env, err := b.IssueAttestation(sigilID, caps, time.Now().Add(ttl))
	if err != nil {
		die("IssueAttestation: %v", err)
	}
	printJSON(env)
}

// --- verify ---

// verify [<envelope.json>] — reads from file or stdin; exits 0=ok, 1=denied.
func runVerify(args []string, storeFlag string) {
	var input []byte
	var err error

	if len(args) > 0 && args[0] != "-" {
		input, err = os.ReadFile(args[0])
		if err != nil {
			die("cannot read %s: %v", args[0], err)
		}
	} else {
		input, err = io.ReadAll(os.Stdin)
		if err != nil {
			die("cannot read stdin: %v", err)
		}
	}

	var env protocol.AttestationEnvelope
	if err := json.Unmarshal(input, &env); err != nil {
		die("invalid JSON: %v", err)
	}

	sc := openStore(storeFlag)
	defer sc.Close()
	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)

	if err := b.VerifyAttestation(&env); err != nil {
		fmt.Fprintf(os.Stderr, "DENIED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

// --- revoke ---

// revoke sigil|cap <id>
func runRevoke(args []string, storeFlag string) {
	if len(args) < 2 {
		die("revoke requires: sigil|cap <id>")
	}
	kind := args[0]
	id := args[1]
	reason := "operator revocation"
	for i := 2; i < len(args); i++ {
		if args[i] == "--reason" {
			reason = nextArg(args, &i, "--reason")
		}
	}

	sc := openStore(storeFlag)
	defer sc.Close()
	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)

	switch kind {
	case "sigil":
		if err := b.RevokeSigil(id, reason, "cli"); err != nil {
			die("RevokeSigil: %v", err)
		}
		fmt.Printf(`{"revoked":"sigil","id":%q}`+"\n", id)
	case "cap":
		entry := protocol.RevocationEntry{
			ID:         id,
			TargetType: "cap",
			Reason:     reason,
			RevokedAt:  time.Now().UTC(),
			RevokedBy:  "cli",
		}
		if err := sc.Revoke(entry); err != nil {
			die("RevokeCap: %v", err)
		}
		fmt.Printf(`{"revoked":"cap","id":%q}`+"\n", id)
	default:
		die("unknown revoke target %q — want: sigil | cap", kind)
	}
	_ = b
}

// --- list ---

// list sigils
func runList(args []string, storeFlag string) {
	if len(args) == 0 || args[0] != "sigils" {
		die("list requires sub-command: sigils")
	}

	sc := openStore(storeFlag)
	defer sc.Close()

	ls, ok := sc.(interface {
		ListSigils() ([]*protocol.Sigil, error)
	})
	if !ok {
		die("store does not support listing sigils")
	}
	sigils, err := ls.ListSigils()
	if err != nil {
		die("ListSigils: %v", err)
	}
	printJSON(sigils)
}

// --- printUsage ---

func printUsage() {
	fmt.Fprintln(os.Stderr, `hanko-broker — Hanko v0.1 broker CLI (OBYW.one internal)

PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
It is NOT related to the teamhanko/hanko project. See README.md §Provenance.

Global flags:
  --store mem|pg   Store backend (default: pg when HANKO_PG_DSN set, else mem)

Commands:
  issue sigil  --subject <id> --pubkey <hex> [--meta k=v ...]
               Issue a new Sigil and persist it.

  issue cap    --sigil <id> --scope <s> --ttl <dur>
               Issue a CapabilityToken bound to a Sigil (dur e.g. 1h, 30m).

  issue attestation
               --sigil <id> [--cap <id> ...] --ttl <dur>
               Issue a signed AttestationEnvelope.

  verify [<envelope.json>|-]
               Verify an AttestationEnvelope (file or stdin). Exit 0=OK, 1=DENIED.

  revoke sigil|cap <id> [--reason <str>]
               Revoke a Sigil or CapabilityToken.

  list sigils  List all stored Sigils (JSON array).

  serve        Run HTTP server (W2 Phase 1 + 2 + W6.2b OIDC provider).
               Flags:
                 --addr <host:port>         default 127.0.0.1:8788 (Tailscale-only)
                 --oidc-policy <path>       JSON policy file (env: HANKO_OIDC_POLICY_PATH)
                 --oidc-audit <path>        JSONL audit append-file (env: HANKO_OIDC_AUDIT_PATH)
                 --oidc-audience <aud>      expected aud claim (env: HANKO_OIDC_AUDIENCE)
                 --oidc-issuers <pairs>     "issuer=jwksURL,issuer=jwksURL"
                                            (env: HANKO_OIDC_ISSUERS)
                                            Empty → OIDC bootstrap endpoint disabled.
                 --oidcp-issuer <url>       OIDC provider issuer URL
                                            (env: HANKO_OIDCP_ISSUER)
                                            e.g. http://100.64.0.2:8788
                                            Empty → OIDC provider façade disabled.
                 --oidcp-config <path>      Clients + users JSON file
                                            (env: HANKO_OIDCP_CONFIG_PATH)
                 --oidcp-audit <path>       JSONL audit append-file
                                            (env: HANKO_OIDCP_AUDIT_PATH)
                 --oidcp-cookie-secure      Set Secure flag on session cookie
                                            (env: HANKO_OIDCP_COOKIE_SECURE=1)
               Public routes (safe for Caddy reverse-proxy):
                 GET  /api/v1/jwks
                 GET  /.well-known/jwks.json
                 GET  /healthz
                 POST /api/v1/sigils/bootstrap-oidc  (when --oidc-issuers set)
                 GET  /.well-known/openid-configuration (when --oidcp-issuer set)
                 GET  /api/v1/oidc/authorize
                 POST /api/v1/oidc/login
                 POST /api/v1/oidc/token
                 GET  /api/v1/oidc/userinfo
               Admin routes (never proxy publicly):
                 (none yet)

  keygen       Generate broker Ed25519 key pair (~/.hanko/broker.key).
  demo         Run in-process end-to-end demonstration (MemStore).
  status       Print broker health JSON.

Environment:
  HANKO_PG_DSN          Postgres DSN (e.g. postgres://user:pass@host/db?sslmode=disable)
  HANKO_BROKER_KEY_PATH Path to broker private key (default: ~/.hanko/broker.key)

  TODO: HANKO_PG_DSN will be replaced by shi-secret://hanko/pg-dsn in W5 once
  the shi secrets broker is live on nuc-dev. The raw DSN env-var is the accepted
  interim pattern (no credentials in source code).`)
}

// --- demo (preserved from W2) ---

func runDemo() {
	fmt.Println("=== Hanko v0.1 — Go reference implementation demo ===")
	fmt.Printf("Protocol version : %s\n\n", protocol.Version)

	issuerPub, issuerPriv, err := hcrypto.GenerateKeyPair()
	must(err, "generate issuer key")
	subjectPub, _, err := hcrypto.GenerateKeyPair()
	must(err, "generate subject key")

	st := store.NewMemStore()
	b := broker.New(st, issuerPub, issuerPriv)

	sigil, err := b.IssueSigil("agent:shi-flow", subjectPub, nil,
		map[string]string{"workspace": "obyw-one"})
	must(err, "issue sigil")
	printJSON(sigil)

	cap, err := b.IssueCap(sigil.ID, "shi-flow:probe:read", time.Now().Add(time.Hour))
	must(err, "issue cap")
	printJSON(cap)

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	must(err, "issue attestation")
	printJSON(env)

	if err := b.VerifyAttestation(env); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFY FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VerifyAttestation: OK")

	if err := broker.VerifyCapScope(cap, "shi-flow:probe:read"); err != nil {
		fmt.Fprintf(os.Stderr, "SCOPE CHECK FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VerifyCapScope(exact match): OK")

	if err := broker.VerifyCapScope(cap, "garage:write:obyw-media"); err != nil {
		fmt.Println("VerifyCapScope(mismatch) correctly denied:", err)
	}

	must(b.RevokeSigil(sigil.ID, "demo revocation", sigil.ID), "revoke sigil")

	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
	must(err, "issue post-revocation attestation")

	if err := b.VerifyAttestation(env2); err != nil {
		fmt.Println("VerifyAttestation(revoked sigil) correctly denied:", err)
	}

	fmt.Println("\n=== Demo complete ===")
}

// --- keygen (preserved from W2) ---

func runKeygen(args []string) {
	out := defaultKeyPath()
	force := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		case "--force":
			force = true
		}
	}

	if _, err := os.Stat(out); err == nil && !force {
		fmt.Fprintf(os.Stderr, "refusing to overwrite existing key at %s (use --force)\n", out)
		os.Exit(1)
	}

	pub, priv, err := hcrypto.GenerateKeyPair()
	must(err, "generate broker key pair")

	if err := os.MkdirAll(filepathDir(out), 0o700); err != nil {
		must(err, "create key directory")
	}
	if err := os.WriteFile(out, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		must(err, "write private key")
	}

	fp := sha256.Sum256(pub)
	fmt.Printf("private_key_path   = %q\n", out)
	fmt.Printf("pubkey_hex         = %q\n", hex.EncodeToString(pub))
	fmt.Printf("pubkey_fingerprint = %q\n", "sha256:"+hex.EncodeToString(fp[:]))
}

// --- helpers ---

func printJSON(v any) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(raw))
}

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR [%s]: %v\n", context, err)
		os.Exit(1)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func mustArgs(args []string, n int, msg string) {
	if len(args) < n {
		die(msg)
	}
}

func nextArg(args []string, i *int, flag string) string {
	*i++
	if *i >= len(args) {
		die("%s requires an argument", flag)
	}
	return args[*i]
}

// extractStoreFlag scans args for --store <val> and returns the remaining args
// and the store flag value.
func extractStoreFlag(args []string) ([]string, string) {
	var out []string
	var storeVal string
	for i := 0; i < len(args); i++ {
		if args[i] == "--store" && i+1 < len(args) {
			i++
			storeVal = args[i]
		} else {
			out = append(out, args[i])
		}
	}
	return out, storeVal
}

func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "broker.key"
	}
	return home + "/.hanko/broker.key"
}

func filepathDir(p string) string {
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "."
	}
	return p[:idx]
}
