-- +goose Up

-- Append-only record of who did what, within which organization. Retrofitting this
-- into a live B2B product is painful, so it ships in the template.
--
-- Nothing in the application ever UPDATEs or DELETEs a row here. actor_user_id
-- is nullable and ON DELETE SET NULL so that deleting a user does not erase the
-- history of their actions.
CREATE TABLE audit_log (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    organization_id     uuid REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id uuid REFERENCES users(id)   ON DELETE SET NULL,
    -- Dotted action name, e.g. "member.role_changed", "organization.created".
    action        text NOT NULL,
    -- What was acted on: a table name and an id, e.g. ("membership", <uuid>).
    target_type   text NOT NULL DEFAULT '',
    target_id     text NOT NULL DEFAULT '',
    -- Free-form detail: the old and new value, the request IP, and so on.
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- The dominant read is "show this organization's activity, newest first". The id is a
-- uuidv7, so it is already time-ordered -- sorting by it avoids a timestamp sort
-- and gives a stable keyset-pagination cursor.
CREATE INDEX audit_log_organization_id_idx ON audit_log (organization_id, id DESC);

-- +goose Down
DROP TABLE audit_log;
