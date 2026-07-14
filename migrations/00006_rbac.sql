-- +goose Up

-- Replaces the single memberships.role string with real RBAC:
--
--   permissions       the vocabulary. One row per enforcement point in the CODE.
--                     Not user-authored -- see the note below.
--   roles             a named bundle of permissions. System roles (organization_id
--                     NULL) ship with the app; organizations may create their own.
--   role_permissions  which permissions a role grants. THE CONFIGURABLE PART.
--   membership_roles  which roles a member holds. A member may hold several;
--                     their permissions are the union.

-- The permission catalog. This table is SEEDED FROM CODE (see
-- internal/identity/permissions.go and Service.SyncPermissions), never written
-- by a user.
--
-- Why: a permission name only means something because some line of Go enforces
-- it. If an organization admin could invent "billing.refund", it would be stored,
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
-- organization_id NULL  => a SYSTEM role: ships with the application, shared by every
--                    organization, and immutable (is_system). owner/admin/member.
-- organization_id set   => a CUSTOM role belonging to one organization, created and edited
--                    at runtime by someone holding roles.manage.
CREATE TABLE roles (
    id         uuid PRIMARY KEY DEFAULT uuidv7(),
    organization_id  uuid REFERENCES organizations(id) ON DELETE CASCADE,
    key        text NOT NULL,              -- stable identifier, e.g. "billing_manager"
    name       text NOT NULL,              -- human label, e.g. "Billing Manager"
    -- is_system marks a role the application depends on. It cannot be edited or
    -- deleted through the API, so an organization cannot lock itself out by, say,
    -- stripping every permission from "owner".
    is_system  boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    -- A system role must have no organization, and a custom role must have one.
    CONSTRAINT roles_system_has_no_organization
        CHECK ((is_system AND organization_id IS NULL) OR (NOT is_system AND organization_id IS NOT NULL))
);

-- Role keys are unique per organization. Two partial indexes rather than one UNIQUE
-- constraint, because NULL never equals NULL in SQL: a plain UNIQUE (organization_id,
-- key) would happily allow two system roles both called "owner".
CREATE UNIQUE INDEX roles_system_key_idx ON roles (key) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX roles_organization_key_idx ON roles (organization_id, key) WHERE organization_id IS NOT NULL;

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
    ('organization.read',          'View the organization and its settings'),
    ('organization.update',        'Change the organization''s name and settings'),
    ('organization.delete',        'Delete the organization entirely'),
    ('members.read',         'View the organization''s members'),
    ('members.invite',       'Invite people to the organization'),
    ('members.remove',       'Remove members from the organization'),
    ('members.assign_roles', 'Change which roles a member holds'),
    ('roles.read',           'View the organization''s roles'),
    ('roles.manage',         'Create, edit, and delete custom roles'),
    ('audit.read',           'Read the organization''s audit log');

-- The three system roles.
INSERT INTO roles (organization_id, key, name, is_system) VALUES
    (NULL, 'owner',  'Owner',  true),
    (NULL, 'admin',  'Admin',  true),
    (NULL, 'member', 'Member', true);

-- owner: everything. This is what the last-owner guard protects -- an organization with
-- no owner would have nobody able to grant roles or delete it.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'owner';

-- admin: the organization administrator. Everything except destroying the organization.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'admin'
  AND p.key <> 'organization.delete';

-- member: can see the organization and who else is in it. Nothing more.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, p.key
FROM roles r CROSS JOIN permissions p
WHERE r.is_system AND r.key = 'member'
  AND p.key IN ('organization.read', 'members.read');

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
