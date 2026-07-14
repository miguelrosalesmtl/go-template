-- +goose Up

-- Global user identities. A user is not owned by an organization: the same person can
-- belong to many organizations via memberships, with a different role in each.
CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    email         citext NOT NULL UNIQUE,
    password_hash text,                    -- nullable: room for SSO/OIDC later
    full_name     text NOT NULL DEFAULT '',
    is_superuser  boolean NOT NULL DEFAULT false,
    is_active     boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Organizations are the isolated top-level accounts. Every organization-owned table in this
-- application carries an organization_id referencing this table.
CREATE TABLE organizations (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A user's link to an organization, carrying their role within it. No row means the
-- user cannot see the organization at all.
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, organization_id)
);

-- The unique index above leads with user_id, which serves "which organizations can
-- this user see". Index organization_id for the reverse: "list this organization's members".
CREATE INDEX memberships_organization_id_idx ON memberships (organization_id);

-- +goose Down
DROP TABLE memberships;
DROP TABLE organizations;
DROP TABLE users;
