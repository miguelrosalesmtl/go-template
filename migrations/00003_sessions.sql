-- +goose Up

-- Opaque session tokens. The plaintext token is returned to the client exactly
-- once at login and never stored: we keep only its SHA-256 hash, so a database
-- leak does not hand an attacker usable credentials.
--
-- A session is valid when revoked_at IS NULL AND expires_at > now(). Revoking
-- is therefore instant, which is the whole reason for choosing DB-backed
-- sessions over stateless JWTs.
CREATE TABLE sessions (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,   -- SHA-256 of the plaintext token
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,             -- null = active
    user_agent   text NOT NULL DEFAULT '',
    ip_address   inet,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- "Revoke every session for this user" (password change, deactivation) and
-- "list my active sessions".
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- Lets the periodic cleanup of dead sessions scan only what it needs.
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- +goose Down
DROP TABLE sessions;
