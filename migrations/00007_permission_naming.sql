-- +goose Up

-- Standardise the permission catalog on <resource>.<action>, with CRUD verbs.
--
-- The old catalog grew three naming philosophies in ten permissions:
--
--   organization.read / organization.update / organization.delete    CRUD
--   members.invite / members.remove                ad-hoc verbs
--   roles.manage                                   one key silently meaning three
--
-- That is survivable at ten permissions and a mess at forty, once queues, jobs,
-- and webhooks arrive. After this migration the rule has no exceptions: adding a
-- resource means adding <resource>.create/read/update/delete, and a developer
-- never has to invent a verb -- nor a customer guess what "manage" covers.
--
-- Note the deliberate absence of organization.create. Every permission here is checked
-- INSIDE an organization (requirePermission runs after requireOrganization, against the roles
-- you hold there). Creating an organization happens when you are not in one yet, so
-- there is nothing to hold a permission against; POST /organizations is guarded by
-- authentication alone. Same reason there is no users.create for registration.

-- The new keys. Descriptions are re-synced from the Go catalog at every startup
-- (Service.SyncPermissions), so these are just enough to satisfy the NOT NULL.
INSERT INTO permissions (key, description) VALUES
    ('invitations.read',   'View pending invitations'),
    ('invitations.create', 'Invite people to the organization'),
    ('invitations.delete', 'Revoke a pending invitation'),
    ('members.update',     'Change which roles a member holds'),
    ('members.delete',     'Remove members from the organization'),
    ('roles.create',       'Create custom roles'),
    ('roles.update',       'Edit custom roles'),
    ('roles.delete',       'Delete custom roles')
ON CONFLICT (key) DO NOTHING;

-- Remap every existing grant BEFORE deleting the old keys: role_permissions has
-- an ON DELETE RESTRICT foreign key into permissions, so dropping a key that any
-- role still grants would fail outright. (That restriction is deliberate --
-- see 00006 -- precisely so a catalog change cannot silently strip authority.)
--
-- One-to-one renames:
INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'invitations.create' FROM role_permissions WHERE permission = 'members.invite'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'members.delete' FROM role_permissions WHERE permission = 'members.remove'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'members.update' FROM role_permissions WHERE permission = 'members.assign_roles'
ON CONFLICT DO NOTHING;

-- roles.manage was three powers wearing one name. Anybody who held it gets all
-- three, so no role loses authority across the migration.
INSERT INTO role_permissions (role_id, permission)
SELECT role_id, v.perm
FROM role_permissions rp
CROSS JOIN (VALUES ('roles.create'), ('roles.update'), ('roles.delete')) AS v(perm)
WHERE rp.permission = 'roles.manage'
ON CONFLICT DO NOTHING;

-- The old members.invite was doing three jobs: it guarded POST /invitations, GET
-- /invitations, AND DELETE /invitations/{id}. Splitting the resource out means all
-- three new keys have to be granted to whoever held it, or a role that could
-- previously revoke an invitation silently loses the ability -- which is exactly
-- the kind of quiet capability loss a renaming migration must not cause.
INSERT INTO role_permissions (role_id, permission)
SELECT rp.role_id, v.perm
FROM role_permissions rp
CROSS JOIN (VALUES ('invitations.read'), ('invitations.delete')) AS v(perm)
WHERE rp.permission = 'members.invite'
ON CONFLICT DO NOTHING;

-- Anyone who could remove members could obviously already see them and their
-- pending invitations.
INSERT INTO role_permissions (role_id, permission)
SELECT DISTINCT role_id, 'invitations.read'
FROM role_permissions
WHERE permission = 'members.remove'
ON CONFLICT DO NOTHING;

-- Now the old keys hold no grants and can go.
DELETE FROM role_permissions
WHERE permission IN ('members.invite', 'members.remove', 'members.assign_roles', 'roles.manage');

DELETE FROM permissions
WHERE key IN ('members.invite', 'members.remove', 'members.assign_roles', 'roles.manage');

-- +goose Down

INSERT INTO permissions (key, description) VALUES
    ('members.invite',       'Invite people to the organization'),
    ('members.remove',       'Remove members from the organization'),
    ('members.assign_roles', 'Change which roles a member holds'),
    ('roles.manage',         'Create, edit, and delete custom roles')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'members.invite' FROM role_permissions WHERE permission = 'invitations.create'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'members.remove' FROM role_permissions WHERE permission = 'members.delete'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, 'members.assign_roles' FROM role_permissions WHERE permission = 'members.update'
ON CONFLICT DO NOTHING;

-- The old model had no way to say "may create roles but not delete them", so a
-- role holding ANY of the three collapses back to the single roles.manage key.
INSERT INTO role_permissions (role_id, permission)
SELECT DISTINCT role_id, 'roles.manage'
FROM role_permissions
WHERE permission IN ('roles.create', 'roles.update', 'roles.delete')
ON CONFLICT DO NOTHING;

DELETE FROM role_permissions
WHERE permission IN ('invitations.read', 'invitations.create', 'invitations.delete',
                     'members.update', 'members.delete',
                     'roles.create', 'roles.update', 'roles.delete');

DELETE FROM permissions
WHERE key IN ('invitations.read', 'invitations.create', 'invitations.delete',
              'members.update', 'members.delete',
              'roles.create', 'roles.update', 'roles.delete');
