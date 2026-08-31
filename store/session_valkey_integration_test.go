//go:build integration

package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// TestValkeyIntegration_CreateAndGet creates a session in a real Valkey and
// reads it back. Requires HANKO_VALKEY_TEST_ADDR and HANKO_PG_TEST_DSN.
func TestValkeyIntegration_CreateAndGet(t *testing.T) {
	valkeyAddr := os.Getenv("HANKO_VALKEY_TEST_ADDR")
	if valkeyAddr == "" {
		t.Skip("HANKO_VALKEY_TEST_ADDR not set — skipping integration test")
	}

	pgDSN := os.Getenv("HANKO_PG_TEST_DSN")
	if pgDSN == "" {
		t.Skip("HANKO_PG_TEST_DSN not set — skipping integration test")
	}

	ctx := context.Background()
	pgStore, err := store.NewPgStore(ctx, pgDSN)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer pgStore.Close()

	pgSessionStore := store.NewPgSessionStore(pgStore)

	ss, err := store.NewValkeyAugmentedSessionStore(valkeyAddr, pgSessionStore)
	if err != nil {
		t.Fatalf("NewValkeyAugmentedSessionStore: %v", err)
	}
	defer ss.Close()

	now := time.Now().UTC()
	sess := &protocol.Session{
		ID:        "integration-test-session-001",
		SigilID:   "integration-sigil-001",
		Type:      protocol.SessionTypeWeb,
		Payload:   map[string]string{"test": "value"},
		CreatedAt: now,
		ExpiresAt: now.Add(store.SessionTTL(protocol.SessionTypeWeb)),
	}

	if err := ss.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Give async Postgres write time to land
	time.Sleep(50 * time.Millisecond)

	got, err := ss.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("expected ID %q, got %q", sess.ID, got.ID)
	}

	m := ss.Metrics()
	if m.ValkeyHit == 0 {
		t.Error("expected ValkeyHit counter > 0 on second read")
	}

	// Clean up
	if err := ss.DeleteSession(sess.ID); err != nil {
		t.Errorf("DeleteSession: %v", err)
	}
}

// TestValkeyIntegration_TTLExpiry_FallsBackToPostgres creates in PG only
// (bypassing Valkey) and verifies the fallback path works.
func TestValkeyIntegration_TTLExpiry_FallsBackToPostgres(t *testing.T) {
	valkeyAddr := os.Getenv("HANKO_VALKEY_TEST_ADDR")
	if valkeyAddr == "" {
		t.Skip("HANKO_VALKEY_TEST_ADDR not set — skipping integration test")
	}
	pgDSN := os.Getenv("HANKO_PG_TEST_DSN")
	if pgDSN == "" {
		t.Skip("HANKO_PG_TEST_DSN not set — skipping integration test")
	}

	ctx := context.Background()
	pgStore, err := store.NewPgStore(ctx, pgDSN)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer pgStore.Close()

	pgSessionStore := store.NewPgSessionStore(pgStore)

	now := time.Now().UTC()
	sess := &protocol.Session{
		ID:        "integration-fallback-session-001",
		SigilID:   "integration-sigil-002",
		Type:      protocol.SessionTypeCLI,
		Payload:   map[string]string{"fallback": "true"},
		CreatedAt: now,
		ExpiresAt: now.Add(store.SessionTTL(protocol.SessionTypeCLI)),
	}

	// Write directly to Postgres (bypass Valkey — simulates TTL expiry)
	if err := pgSessionStore.CreateSession(sess); err != nil {
		t.Fatalf("pgSessionStore.CreateSession: %v", err)
	}

	ss, err := store.NewValkeyAugmentedSessionStore(valkeyAddr, pgSessionStore)
	if err != nil {
		t.Fatalf("NewValkeyAugmentedSessionStore: %v", err)
	}
	defer ss.Close()

	got, err := ss.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession (fallback): %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("expected ID %q, got %q", sess.ID, got.ID)
	}

	m := ss.Metrics()
	if m.ValkeyMiss == 0 {
		t.Error("expected ValkeyMiss > 0 (Postgres-only write)")
	}
	if m.PostgresFallback == 0 {
		t.Error("expected PostgresFallback > 0")
	}

	// Clean up
	_ = ss.DeleteSession(sess.ID)
}
