-- Hanko v0.1 — migration 002: session persistence (audit mirror)
-- Primary store is Valkey; this table is audit truth per NF5.

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID        PRIMARY KEY,
    sigil_id    UUID        NOT NULL REFERENCES sigils(id),
    type        TEXT        NOT NULL CHECK (type IN ('operator','cli','web')),
    payload     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_sigil_id ON sessions(sigil_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

INSERT INTO hanko_schema_migrations(version) VALUES (2) ON CONFLICT DO NOTHING;
