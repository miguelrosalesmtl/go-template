package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Everything that reads or writes roles and their permissions.
//
// THE TENANT-SCOPING RULE APPLIES HERE TOO, with a twist: a role is visible to a
// tenant if it is a system role (tenant_id IS NULL, shared by everyone) OR it
// belongs to that tenant. That disjunction appears in every WHERE clause below,
// and it is what stops tenant A from assigning, editing, or deleting tenant B's
// custom role by guessing its id.

// roleColumns is qualified with the alias "r" because every one of these queries
// joins roles against role_permissions, and both tables have an id.
const roleColumns = `r.id, r.tenant_id, r.key, r.name, r.is_system, r.created_at, r.updated_at`

// visibleToTenant is the predicate that decides whether a tenant may see a role:
// system roles are shared by all, custom roles belong to exactly one tenant.
const visibleToTenant = `(r.tenant_id IS NULL OR r.tenant_id = $1)`

// ListRoles returns every role the tenant can use -- the three system roles plus
// its own custom ones -- each with its permissions.
func (r *Repository) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	// LEFT JOIN, not JOIN: a role with no permissions yet is still a role, and an
	// inner join would make it vanish from the list.
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE `+visibleToTenant+`
		 ORDER BY r.is_system DESC, r.key`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list roles: %w", err)
	}
	defer rows.Close()

	return collectRoles(rows)
}

// GetRole returns one role, but only if the tenant may see it. A role belonging
// to another tenant is ErrNotFound, exactly as if it did not exist.
func (r *Repository) GetRole(ctx context.Context, tenantID, roleID uuid.UUID) (Role, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE `+visibleToTenant+` AND r.id = $2`,
		tenantID, roleID,
	)
	if err != nil {
		return Role{}, fmt.Errorf("identity: get role: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return Role{}, err
	}
	if len(roles) == 0 {
		return Role{}, ErrNotFound
	}
	return roles[0], nil
}

// GetRoleByKey resolves a role by its key within a tenant, checking the tenant's
// own roles and the system roles. Used to find "owner" and to seed a new tenant.
func (r *Repository) GetRoleByKey(ctx context.Context, tenantID uuid.UUID, key string) (Role, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE `+visibleToTenant+` AND r.key = $2`,
		tenantID, key,
	)
	if err != nil {
		return Role{}, fmt.Errorf("identity: get role by key: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return Role{}, err
	}
	if len(roles) == 0 {
		return Role{}, ErrNotFound
	}
	return roles[0], nil
}

// GetRolesByIDs resolves a set of role ids, but ONLY those the tenant may see.
//
// If any requested id is missing -- because it does not exist, or because it
// belongs to another tenant -- this returns ErrNotFound rather than silently
// assigning the subset it could find. That strictness is the point: an admin of
// tenant A passing tenant B's role id must fail, not quietly get a shorter list.
func (r *Repository) GetRolesByIDs(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Role, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE `+visibleToTenant+` AND r.id = ANY($2)
		 ORDER BY r.is_system DESC, r.key`,
		tenantID, ids,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: get roles by ids: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}

	// Deduplicate the request before comparing counts, so passing the same id
	// twice is not mistaken for a missing role.
	wanted := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	if len(roles) != len(wanted) {
		return nil, ErrNotFound
	}
	return roles, nil
}

// CreateRole inserts a custom role and its permissions. It must run inside a
// transaction: a role that committed without its permissions would be a role
// that grants nothing.
func (r *Repository) CreateRole(
	ctx context.Context, tenantID uuid.UUID, key, name string, perms PermissionSet,
) (Role, error) {
	var role Role
	err := r.db.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, key, name, is_system)
		 VALUES ($1, $2, $3, false)
		 RETURNING id, tenant_id, key, name, is_system, created_at, updated_at`,
		tenantID, key, name,
	).Scan(&role.ID, &role.TenantID, &role.Key, &role.Name, &role.IsSystem,
		&role.CreatedAt, &role.UpdatedAt)

	if isUniqueViolation(err, "roles_tenant_key_idx") {
		return Role{}, ErrRoleKeyTaken
	}
	if err != nil {
		return Role{}, fmt.Errorf("identity: create role: %w", err)
	}

	if err := r.replaceRolePermissions(ctx, role.ID, perms); err != nil {
		return Role{}, err
	}
	role.Permissions = perms
	return role, nil
}

// UpdateRole renames a custom role and replaces its permission set wholesale.
//
// tenant_id is in the WHERE clause AND is_system is excluded, so this can touch
// neither another tenant's role nor a system role.
func (r *Repository) UpdateRole(
	ctx context.Context, tenantID, roleID uuid.UUID, name string, perms PermissionSet,
) (Role, error) {
	var role Role
	err := r.db.QueryRow(ctx,
		`UPDATE roles SET name = $3, updated_at = now()
		 WHERE id = $2 AND tenant_id = $1 AND NOT is_system
		 RETURNING id, tenant_id, key, name, is_system, created_at, updated_at`,
		tenantID, roleID, name,
	).Scan(&role.ID, &role.TenantID, &role.Key, &role.Name, &role.IsSystem,
		&role.CreatedAt, &role.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Either it does not exist, or it belongs to someone else, or it is a
		// system role. The service distinguishes the last case for a better
		// message; from here they are all "you cannot update that".
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("identity: update role: %w", err)
	}

	if err := r.replaceRolePermissions(ctx, roleID, perms); err != nil {
		return Role{}, err
	}
	role.Permissions = perms
	return role, nil
}

// DeleteRole removes a custom role belonging to this tenant.
//
// membership_roles.role_id is ON DELETE RESTRICT, so if anybody still holds the
// role, Postgres refuses and this returns ErrRoleInUse. Deleting a role should
// not silently strip people's access as a side effect.
func (r *Repository) DeleteRole(ctx context.Context, tenantID, roleID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM roles WHERE id = $2 AND tenant_id = $1 AND NOT is_system`,
		tenantID, roleID,
	)
	if isForeignKeyViolation(err, "membership_roles_role_id_fkey") {
		return ErrRoleInUse
	}
	if err != nil {
		return fmt.Errorf("identity: delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// replaceRolePermissions swaps a role's permission set for a new one. Delete then
// insert, inside the caller's transaction, so no moment exists in which the role
// holds a mixture of the old and new sets.
func (r *Repository) replaceRolePermissions(ctx context.Context, roleID uuid.UUID, perms PermissionSet) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return fmt.Errorf("identity: clear role permissions: %w", err)
	}

	for _, p := range perms.Slice() {
		_, err := r.db.Exec(ctx,
			`INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)`,
			roleID, p,
		)
		if isForeignKeyViolation(err, "role_permissions_permission_fkey") {
			// The permission is not in the catalog: no code enforces it. The
			// service validates against Catalog first, so reaching here means the
			// database and the binary disagree.
			return fmt.Errorf("%w: %q is not a permission this application enforces", ErrValidation, p)
		}
		if err != nil {
			return fmt.Errorf("identity: grant permission %q: %w", p, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- assignment

// LoadMemberRoles returns the roles a user holds in a tenant, with their
// permissions.
//
// It returns ErrNotFound when there is no membership at all -- which is the
// authorization check every tenant-scoped request performs. A membership that
// exists but holds no roles yields an empty slice, not an error; the service
// forbids creating that state, but the repository reports honestly what it finds.
func (r *Repository) LoadMemberRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]Role, error) {
	// The LEFT JOINs hang off memberships, so a member with no roles still
	// produces one row (with NULLs) and is distinguishable from a non-member,
	// who produces none.
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM memberships m
		 LEFT JOIN membership_roles mr ON mr.membership_id = m.id
		 LEFT JOIN roles r            ON r.id = mr.role_id
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE m.user_id = $2 AND m.tenant_id = $1
		 ORDER BY r.is_system DESC, r.key`,
		tenantID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: load member roles: %w", err)
	}
	defer rows.Close()

	roles, any, err := collectRolesNullable(rows)
	if err != nil {
		return nil, err
	}
	if !any {
		return nil, ErrNotFound // no membership: not a member of this tenant
	}
	return roles, nil
}

// SetMembershipRoles replaces the set of roles a membership holds. Must run in a
// transaction.
func (r *Repository) SetMembershipRoles(ctx context.Context, membershipID uuid.UUID, roleIDs []uuid.UUID) error {
	if _, err := r.db.Exec(ctx,
		`DELETE FROM membership_roles WHERE membership_id = $1`, membershipID,
	); err != nil {
		return fmt.Errorf("identity: clear membership roles: %w", err)
	}

	for _, id := range roleIDs {
		if _, err := r.db.Exec(ctx,
			`INSERT INTO membership_roles (membership_id, role_id) VALUES ($1, $2)`,
			membershipID, id,
		); err != nil {
			return fmt.Errorf("identity: assign role %s: %w", id, err)
		}
	}
	return nil
}

// CountOwners returns how many members hold the system owner role in this tenant.
//
// Call it inside the same transaction as the write it guards, after LockTenant,
// or two concurrent requests each removing one of the last two owners will both
// see a count of 2 and both succeed.
func (r *Repository) CountOwners(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(DISTINCT m.id)
		 FROM memberships m
		 JOIN membership_roles mr ON mr.membership_id = m.id
		 JOIN roles r             ON r.id = mr.role_id
		 WHERE m.tenant_id = $1 AND r.is_system AND r.key = $2`,
		tenantID, RoleKeyOwner,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("identity: count owners: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------- scanning

// collectRoles folds the role x permission rows produced by the LEFT JOIN back
// into one Role per id, with its permissions gathered into a set.
//
// The join necessarily repeats a role's columns once per permission it holds;
// this is where that fan-out is undone.
func collectRoles(rows pgx.Rows) ([]Role, error) {
	roles, _, err := collectRolesNullable(rows)
	return roles, err
}

// collectRolesNullable is collectRoles for queries whose LEFT JOIN can produce a
// row with no role at all (a member holding none). It also reports whether any
// row was seen, which is how "no membership" is told apart from "membership with
// no roles".
func collectRolesNullable(rows pgx.Rows) (out []Role, anyRow bool, err error) {
	byID := map[uuid.UUID]*Role{}
	var order []uuid.UUID

	for rows.Next() {
		anyRow = true

		// Every column is scanned into a pointer, because a LEFT JOIN that matched
		// nothing yields NULLs across the whole right-hand side.
		var (
			id, tenantID         *uuid.UUID
			key, name            *string
			isSystem             *bool
			createdAt, updatedAt *time.Time
			perm                 *Permission
		)
		if err := rows.Scan(&id, &tenantID, &key, &name, &isSystem, &createdAt, &updatedAt, &perm); err != nil {
			return nil, false, fmt.Errorf("identity: scan role: %w", err)
		}
		if id == nil {
			continue // a membership holding no roles: the row exists, the role does not
		}

		role, seen := byID[*id]
		if !seen {
			role = &Role{
				ID:          *id,
				TenantID:    tenantID,
				Key:         *key,
				Name:        *name,
				IsSystem:    *isSystem,
				Permissions: PermissionSet{},
				CreatedAt:   *createdAt,
				UpdatedAt:   *updatedAt,
			}
			byID[*id] = role
			order = append(order, *id)
		}
		if perm != nil {
			role.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("identity: iterate roles: %w", err)
	}

	out = make([]Role, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, anyRow, nil
}

// ---------------------------------------------------------------- helpers

// rolesToIDs is a small convenience used by the service when it has roles and
// needs to store the assignment.
func rolesToIDs(roles []Role) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.ID)
	}
	return out
}

// hasOwnerRole reports whether any of the roles is the system owner role.
func hasOwnerRole(roles []Role) bool {
	for _, r := range roles {
		if r.IsSystem && r.Key == RoleKeyOwner {
			return true
		}
	}
	return false
}
