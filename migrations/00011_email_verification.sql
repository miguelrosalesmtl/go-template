-- +goose Up

-- Email verification.
--
-- users.email was already unique and case-insensitive, but nothing ever checked
-- that the person who typed it CONTROLS it. That mattered less before there was a
-- password reset; now it is the whole foundation, because a reset is only as
-- trustworthy as the mailbox it is sent to. An unverified address is an account
-- somebody else may be able to take.
ALTER TABLE users ADD COLUMN email_verified_at timestamptz;

-- The verification token. Same shape as invitations and password resets: random,
-- stored only as its SHA-256 digest, single-use, expiring.
CREATE TABLE email_verifications (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The address being verified, which is NOT necessarily users.email forever:
    -- keeping it here means a later "change your email" flow can reuse this table
    -- without pretending the new address is already the account's.
    email      citext NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_verifications_user_id_idx    ON email_verifications (user_id);
CREATE INDEX email_verifications_expires_at_idx ON email_verifications (expires_at);

-- Existing users predate verification. Marking them verified is the only sane
-- migration: the alternative locks out everybody who already had an account, for a
-- rule that did not exist when they signed up.
UPDATE users SET email_verified_at = created_at;

-- +goose Down
DROP TABLE email_verifications;
ALTER TABLE users DROP COLUMN email_verified_at;
