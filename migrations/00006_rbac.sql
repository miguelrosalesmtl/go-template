-- +goose Up

-- Replaces the single memberships.role string with real RBAC:
--
--   permissions       the vocabulary. One row per enforcement point in the CODE.
--                     Not user-authored -- see the note below.
--   roles             a named bundle of permissions. System roles (tenant_id
--                     NULL) ship with the app; tenants may create their own.
--   role_permissions  which permissions a role grants. THE CONFIGURABLE PART.
--   membership_roles  which roles a member holds. A member may hold several;
--                     their permissions are the union.

-- The permission catalog. This table is SEEDED FROM CODE (see
-- internal/identity/permissions.go and Service.SyncPermissions), never written
-- by a user.
--
-- Why: a permission name only means something because some line of Go enforces
-- it. If a tenant admin could invent "billing.refund", it would be stored,
-- assigned to a role, and rendered with a checkbox in the UI -- while enforcing
-- absolutely nothing. It would look like it worked and grant zero. The foreign
-- key from role_permissions into this table is what makes that impossible: you
-- cannot assign a permission that no code enforces.
CREATE TABLE permissions (
    key         text PRIMARY KEY,          -- e.g. "members.invite"
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- A role is a named bundle of permissions.
--
-- tenant_id NULL  => a SYSTEM role: ships with the application, shared by every
--                    tenant, and immutable (is_system). owner/admin/member.
-- tenant_id set   => a CUSTOM role belonging to one tenant, created and edited
--                    at runtime by someone holding roles.manage.
CREATE TABLE roles (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  uuid REFERENCES tenants(id) ON DELETE CASCADE,
    key        text NOT NULL,              -- stable identifier, e.g. "billing_manager"
    name       text NOT NULL,              -- human label, e.g. "Billing Manager"
    -- is_system marks a role the application depends on. It cannot be edited or
    -- deleted through the API, so a tenant cannot lock itself out by, say,
    -- stripping every permission from "owner".
    is_system  boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    -- A system role must have no tenant, and a custom role must have one.
    CONSTRAINT roles_system_has_no_tenant
        CHECK ((is_system AND tenant_id IS NULL) OR (NOT is_system AND tenant_id IS NOT NULL))
);

-- Role keys are unique per tenant. Two partial indexes rather than one UNIQUE
-- constraint, because NULL never equals NULL in SQL: a plain UNIQUE (tenant_id,
-- key) would happily allow two system roles both called "owner".
CREATE UNIQUE INDEX roles_system_key_idx ON roles (key) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX roles_tenant_key_idx ON roles (tenant_id, key) WHERE tenant_id IS NOT NULL;

-- Which permissions a role grants. This is the part customers configure.
CREATE TABLE role_permissions (
    role_id    uuid NOT NULL REFERENCES roles(id)          ON DELETE CASCADE,
    permission text NOT NULL REFERENCES permissions(key)   ON DELETE RESTRICT,
    PRIMARY KEY (role_id, permission)
);

-- ON DELETE RESTRICT above, deliberately: removing a permission from the catalog
-- while roles still grant it should fail loudly rather than silently strip
-- authority from whoever held it.

-- Which roles a member holds. Many-to-many: a user can be a "member" AND a
-- "billing manager", and their permissions are the union of both.
--
-- Without this, giving a member one extra power means cloning the whole "member"
-- role into a new one -- and you end up with a combinatorial pile of roles.
CREATE TABLE membership_roles (
    membership_id uuid NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    role_id       uuid NOT NULL REFERENCES roles(id)       ON DELETE RESTRICT,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (membership_id, role_id)
);

-- ON DELETE RESTRICT on role_id: deleting a role that people still hold must
-- fail. The service unassigns first, so this is a backstop against a mistake
-- silently stripping someone's access.

CREATE INDEX membership_roles_role_id_idx ON membership_roles (role_id);

-- ---------------------------------------------------------------- seed

-- The catalog. Kept in sync at startup by Service.SyncPermissions, which upserts
-- from the Go constants -- so adding a permission later needs a code change, not
-- a migration. Seeding here means a freshly migrated database is usable at once.
INSERT INTO permissions (key, description) VALUES
    ('tenant.read',          'View the tenant and its settings'),
    ('tenant.update',        'Change the tenant''s name and settings'),
    ('tenant.delete',        'Delete the tenant entirely'),
    ('members.read',         'View the tenant''s members'),
    ('members.invite',       'Invite people to the tenant'),
    ('members.remove',       'Remove members from the tenant'),
    ('members.assign_roles', 'Change which roles a member holds'),
    ('roles.read',           'View the tenant''s roles'),
    ('roles.manage',         'Create, edit, and delete custom roles'),
    ('audit.read',           'Read the tenant''s audit log');

-- The three system roles.
INSERT INTO roles (tenant_id, key, name, is_system) VALUES
    (NULL, 'owner',  'Owner',  true),
    (NULL, 'admin',  'Admin',  true),
    (NULL, 'member', 'Member', true);

-- owner: everything. This is what the last-owner guard protects -- a tenant with
-- no owner would have nobody able to grant roles or delete it.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'owner';

-- admin: the tenant administrator. Everything except destroying the tenant.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'admin'
  AND p.key <> 'tenant.delete';

-- member: can see the tenant and who else is in it. Nothing more.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'member'
  AND p.key IN ('tenant.read', 'members.read');

-- ---------------------------------------------------------------- migrate data

-- Carry every existing membership's role string across to the new join table.
-- 'owner' | 'admin' | 'member' map one-to-one onto the system roles above.
INSERT INTO membership_roles (membership_id, role_id)
SELECT m.id, r.id
FROM memberships m
JOIN roles r ON r.is_system AND r.key = m.role;

-- The old column is now a lie: authority lives in membership_roles.
ALTER TABLE memberships DROP COLUMN role;

-- Invitations carried a role string too. Point them at a role row instead, so an
-- invitation can offer a CUSTOM role and not just one of the three built-ins.
ALTER TABLE invitations ADD COLUMN role_id uuid REFERENCES roles(id) ON DELETE CASCADE;

UPDATE invitations i
SET role_id = r.id
FROM roles r
WHERE r.is_system AND r.key = i.role;

ALTER TABLE invitations ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE invitations DROP COLUMN role;

-- +goose Down

ALTER TABLE invitations ADD COLUMN role text;
UPDATE invitations i SET role = r.key FROM roles r WHERE r.id = i.role_id;
ALTER TABLE invitations ALTER COLUMN role SET NOT NULL;
ALTER TABLE invitations ADD CONSTRAINT invitations_role_check
    CHECK (role IN ('owner', 'admin', 'member'));
ALTER TABLE invitations DROP COLUMN role_id;

ALTER TABLE memberships ADD COLUMN role text;
-- A member may now hold several roles, but the old column held exactly one. Keep
-- the most powerful, so nobody is silently downgraded by rolling back.
UPDATE memberships m SET role = (
    SELECT r.key FROM membership_roles mr
    JOIN roles r ON r.id = mr.role_id
    WHERE mr.membership_id = m.id AND r.is_system
    ORDER BY CASE r.key WHEN 'owner' THEN 3 WHEN 'admin' THEN 2 ELSE 1 END DESC
    LIMIT 1
);
-- Anyone holding only custom roles has no equivalent in the old model.
UPDATE memberships SET role = 'member' WHERE role IS NULL;
ALTER TABLE memberships ALTER COLUMN role SET NOT NULL;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'member'));

DROP TABLE membership_roles;
DROP TABLE role_permissions;
DROP TABLE roles;
DROP TABLE permissions;
