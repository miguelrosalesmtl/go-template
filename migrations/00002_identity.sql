-- +goose Up

-- Global user identities. A user is not owned by a tenant: the same person can
-- belong to many tenants via memberships, with a different role in each.
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

-- Tenants are the isolated top-level accounts. Every tenant-owned table in this
-- application carries a tenant_id referencing this table.
CREATE TABLE tenants (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- A user's link to a tenant, carrying their role within it. No row means the
-- user cannot see the tenant at all.
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id    uuid NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, tenant_id)
);

-- The unique index above leads with user_id, which serves "which tenants can
-- this user see". Index tenant_id for the reverse: "list this tenant's members".
CREATE INDEX memberships_tenant_id_idx ON memberships (tenant_id);

-- +goose Down
DROP TABLE memberships;
DROP TABLE tenants;
DROP TABLE users;
