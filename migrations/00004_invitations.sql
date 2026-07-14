-- +goose Up

-- An invitation lets an organization admin add someone to their organization by email,
-- before that person necessarily has a user account. Accepting an invitation is
-- what creates the membership row.
--
-- Like sessions, we store only the SHA-256 hash of the invitation token; the
-- plaintext goes out in the invite email/link and is never persisted.
CREATE TABLE invitations (
    id           uuid PRIMARY KEY DEFAULT uuidv7(),
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email        citext NOT NULL,
    role         text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    token_hash   bytea NOT NULL UNIQUE,
    invited_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invitations_organization_id_idx ON invitations (organization_id);

-- At most one live invitation per (organization, email). Accepted and revoked rows are
-- excluded so they stay as history and don't block a re-invite. Expired rows are
-- deliberately NOT excluded -- now() is not immutable and cannot appear in an
-- index predicate; the service treats an expired row as re-issuable instead.
CREATE UNIQUE INDEX invitations_pending_email_idx
    ON invitations (organization_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- +goose Down
DROP TABLE invitations;
