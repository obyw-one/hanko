package store_test

import (
	"fmt"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// MockValkeyBackend simulates Valkey hit/miss behavior for unit tests.
// It implements store.MockableValkeyBackend.
type MockValkeyBackend struct {
	// HitSession — if non-nil, GetSession returns it (cache hit).
	// If nil, GetSession returns (nil, store.ErrValkeyMiss).
	HitSession *protocol.Session

	// Latency simulates artificial Valkey latency.
	Latency time.Duration

	// Call trackers.
	CreateCalled bool
	GetCalled    bool
	DeleteCalled bool
}

func (m *MockValkeyBackend) ValkeyCreate(s *protocol.Session) error {
	if m.Latency > 0 {
		time.Sleep(m.Latency)
	}
	m.CreateCalled = true
	return nil
}

func (m *MockValkeyBackend) ValkeyGet(id string) (*protocol.Session, error) {
	if m.Latency > 0 {
		time.Sleep(m.Latency)
	}
	m.GetCalled = true
	if m.HitSession != nil && m.HitSession.ID == id {
		return m.HitSession, nil
	}
	return nil, store.ErrValkeyMiss
}

func (m *MockValkeyBackend) ValkeyDelete(id string) error {
	if m.Latency > 0 {
		time.Sleep(m.Latency)
	}
	m.DeleteCalled = true
	return nil
}

// MockPgSessionStore is an in-memory SessionStore for unit tests.
type MockPgSessionStore struct {
	Sessions  map[string]*protocol.Session
	GetCalled bool
}

// NewMockPgSessionStore returns an initialised MockPgSessionStore.
func NewMockPgSessionStore() *MockPgSessionStore {
	return &MockPgSessionStore{Sessions: make(map[string]*protocol.Session)}
}

func (m *MockPgSessionStore) CreateSession(s *protocol.Session) error {
	m.Sessions[s.ID] = s
	return nil
}

func (m *MockPgSessionStore) GetSession(id string) (*protocol.Session, error) {
	m.GetCalled = true
	s, ok := m.Sessions[id]
	if !ok {
		return nil, fmt.Errorf("store: session %s not found", id)
	}
	return s, nil
}

func (m *MockPgSessionStore) UpdateSession(s *protocol.Session) error {
	m.Sessions[s.ID] = s
	return nil
}

func (m *MockPgSessionStore) DeleteSession(id string) error {
	delete(m.Sessions, id)
	return nil
}

// Compile-time assertion: MockPgSessionStore satisfies store.SessionStore.
var _ store.SessionStore = (*MockPgSessionStore)(nil)
