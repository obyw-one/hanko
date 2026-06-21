// Package store — session types, interface, and helpers.
package store

import (
	"sync/atomic"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
)

// SessionStore is the interface for session persistence backends.
// ValkeyAugmentedSessionStore implements this by wrapping a Postgres backend
// with a Valkey cache layer.
type SessionStore interface {
	CreateSession(s *protocol.Session) error
	GetSession(id string) (*protocol.Session, error)
	UpdateSession(s *protocol.Session) error
	DeleteSession(id string) error
}

// SessionTTL returns the canonical TTL duration for the given SessionType.
//
//   - operator → 7 days
//   - cli      → 1 hour
//   - web      → 30 minutes
func SessionTTL(t protocol.SessionType) time.Duration {
	switch t {
	case protocol.SessionTypeOperator:
		return 7 * 24 * time.Hour
	case protocol.SessionTypeCLI:
		return 1 * time.Hour
	case protocol.SessionTypeWeb:
		return 30 * time.Minute
	default:
		return 30 * time.Minute
	}
}

// ErrValkeyMiss is returned by MockableValkeyBackend.ValkeyGet when the key
// is not in the cache (either a true miss or TTL expiry). It is also
// re-exported for test code to import.
var ErrValkeyMiss = errValkeyMiss{}

type errValkeyMiss struct{}

func (e errValkeyMiss) Error() string { return "valkey: cache miss" }

// MockableValkeyBackend is the seam used by unit tests to inject a fake
// Valkey without requiring a real server. The real Valkey path is wired
// inside ValkeyAugmentedSessionStore; tests supply a mock via
// NewValkeyAugmentedSessionStoreWithMock.
type MockableValkeyBackend interface {
	ValkeyCreate(s *protocol.Session) error
	ValkeyGet(id string) (*protocol.Session, error)
	ValkeyDelete(id string) error
}

// SessionMetrics holds atomic counters for the Valkey<→Postgres session store.
// Use Metrics() to snapshot them.
type SessionMetrics struct {
	ValkeyHit        int64
	ValkeyMiss       int64
	PostgresFallback int64
	ValkeyWriteError int64
}

// sessionMetricsAtomic holds live counters (unexported; snapshotted via Metrics()).
type sessionMetricsAtomic struct {
	valkeyHit        atomic.Int64
	valkeyMiss       atomic.Int64
	postgresFallback atomic.Int64
	valkeyWriteError atomic.Int64
}

func (a *sessionMetricsAtomic) snapshot() SessionMetrics {
	return SessionMetrics{
		ValkeyHit:        a.valkeyHit.Load(),
		ValkeyMiss:       a.valkeyMiss.Load(),
		PostgresFallback: a.postgresFallback.Load(),
		ValkeyWriteError: a.valkeyWriteError.Load(),
	}
}
