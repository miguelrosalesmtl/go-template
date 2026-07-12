-- +goose Up

-- Password reset. Without it, the first user who forgets their password is locked
-- out of the product permanently -- there is no other recovery path, not even a
-- superuser one, because no route can set another person's password.
--
-- Structurally this is the invitation table again: a random token, stored only as
-- its SHA-256 digest, with an expiry and a single use. The plaintext exists in the
-- email and nowhere else, so a leak of this table hands an attacker nothing.
CREATE TABLE password_resets (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,     -- SHA-256 of the plaintext token
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,               -- null = still usable
    created_at timestamptz NOT NULL DEFAULT now(),

    -- The request records where it came from, because a password-reset request is
    -- the loudest thing an attacker does while probing an account they do not own.
    ip_address inet,
    user_agent text NOT NULL DEFAULT ''
);

-- "Invalidate every outstanding reset for this user" -- which is what issuing a
-- new one, and completing one, both do.
CREATE INDEX password_resets_user_id_idx ON password_resets (user_id);

-- The reaper prunes spent and expired rows.
CREATE INDEX password_resets_expires_at_idx ON password_resets (expires_at);

-- +goose Down
DROP TABLE password_resets;
