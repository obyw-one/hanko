package store_test

import (
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// newTestSession returns a Session with sensible defaults for testing.
func newTestSession(id string, t protocol.SessionType) *protocol.Session {
	now := time.Now().UTC()
	return &protocol.Session{
		ID:        id,
		SigilID:   "sigil-uuid-" + id,
		Type:      t,
		Payload:   map[string]string{"key": "value"},
		CreatedAt: now,
		ExpiresAt: now.Add(store.SessionTTL(t)),
	}
}

// TestSessionCreate_WritesValkeyAndPostgres asserts that CreateSession
// calls both Valkey and Postgres backends via MockValkeyBackend.
func TestSessionCreate_WritesValkeyAndPostgres(t *testing.T) {
	mockPg := NewMockPgSessionStore()
	mockValkey := &MockValkeyBackend{}

	ss := store.NewValkeyAugmentedSessionStoreWithMock(mockValkey, mockPg)

	sess := newTestSession("sess-create-001", protocol.SessionTypeOperator)
	if err := ss.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}

	// Wait briefly for async Postgres write
	time.Sleep(10 * time.Millisecond)

	if !mockValkey.CreateCalled {
		t.Error("expected Valkey CreateSession to be called")
	}
	if _, ok := mockPg.Sessions[sess.ID]; !ok {
		t.Error("expected Postgres CreateSession to be called (async)")
	}
}

// TestSessionRead_HitsValkeyFirst_Under5ms asserts that a Valkey cache hit
// returns within 5ms (mock returns immediately).
func TestSessionRead_HitsValkeyFirst_Under5ms(t *testing.T) {
	sess := newTestSession("sess-read-hit-001", protocol.SessionTypeCLI)

	mockPg := NewMockPgSessionStore()
	mockValkey := &MockValkeyBackend{
		HitSession: sess,
		Latency:    0,
	}

	ss := store.NewValkeyAugmentedSessionStoreWithMock(mockValkey, mockPg)

	start := time.Now()
	got, err := ss.GetSession(sess.ID)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GetSession: unexpected error: %v", err)
	}
	if got == nil || got.ID != sess.ID {
		t.Errorf("expected session %q, got %v", sess.ID, got)
	}
	if elapsed > 5*time.Millisecond {
		t.Errorf("Valkey hit should return in <5ms; took %v", elapsed)
	}
	if !mockValkey.GetCalled {
		t.Error("expected Valkey GetSession to be called")
	}
	if mockPg.GetCalled {
		t.Error("expected Postgres NOT to be called on Valkey hit")
	}
}

// TestSessionRead_TTLExpiry_FallsBackToPostgres asserts that when Valkey
// returns a miss (HitSession == nil), GetSession falls back to Postgres.
func TestSessionRead_TTLExpiry_FallsBackToPostgres(t *testing.T) {
	sess := newTestSession("sess-read-miss-001", protocol.SessionTypeWeb)
	mockPg := NewMockPgSessionStore()
	mockPg.Sessions[sess.ID] = sess

	mockValkey := &MockValkeyBackend{
		HitSession: nil, // cache miss
	}

	ss := store.NewValkeyAugmentedSessionStoreWithMock(mockValkey, mockPg)

	got, err := ss.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession (Postgres fallback): unexpected error: %v", err)
	}
	if got == nil || got.ID != sess.ID {
		t.Errorf("expected session %q from Postgres, got %v", sess.ID, got)
	}
	if !mockValkey.GetCalled {
		t.Error("expected Valkey GetSession to be attempted (even on miss)")
	}
	if !mockPg.GetCalled {
		t.Error("expected Postgres GetSession to be called on Valkey miss")
	}

	m := ss.Metrics()
	if m.ValkeyMiss == 0 {
		t.Error("expected ValkeyMiss counter > 0")
	}
	if m.PostgresFallback == 0 {
		t.Error("expected PostgresFallback counter > 0")
	}
}

// TestSessionDelete_DeletesBothStores asserts that DeleteSession removes
// the session from both Valkey and Postgres backends.
func TestSessionDelete_DeletesBothStores(t *testing.T) {
	sess := newTestSession("sess-delete-001", protocol.SessionTypeOperator)
	mockPg := NewMockPgSessionStore()
	mockPg.Sessions[sess.ID] = sess

	mockValkey := &MockValkeyBackend{HitSession: sess}

	ss := store.NewValkeyAugmentedSessionStoreWithMock(mockValkey, mockPg)

	if err := ss.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession: unexpected error: %v", err)
	}

	if !mockValkey.DeleteCalled {
		t.Error("expected Valkey DeleteSession to be called")
	}
	if _, ok := mockPg.Sessions[sess.ID]; ok {
		t.Error("expected Postgres session to be deleted")
	}
}

// TestSessionCreate_ConfigurableTTL_Operator7d_CLI1h_Web30m checks that
// SessionTTL returns the correct duration for each SessionType.
func TestSessionCreate_ConfigurableTTL_Operator7d_CLI1h_Web30m(t *testing.T) {
	cases := []struct {
		sessionType protocol.SessionType
		wantTTL     time.Duration
	}{
		{protocol.SessionTypeOperator, 7 * 24 * time.Hour},
		{protocol.SessionTypeCLI, 1 * time.Hour},
		{protocol.SessionTypeWeb, 30 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(string(tc.sessionType), func(t *testing.T) {
			got := store.SessionTTL(tc.sessionType)
			if got != tc.wantTTL {
				t.Errorf("SessionTTL(%s) = %v; want %v", tc.sessionType, got, tc.wantTTL)
			}
		})
	}
}
