package identity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// Repository is the only code in the application that writes SQL for identity
// tables.
//
// THE ORGANIZATION-SCOPING RULE: every method that touches an organization-owned table takes
// organizationID as a parameter and puts it in the WHERE clause -- even when the row's
// primary key would already be unique. Filtering by id alone is what turns a
// guessed UUID into a cross-organization read. The isolation test in
// repository_test.go exists to keep this rule honest.
type Repository struct {
	db database.DB
}

// NewRepository returns a Repository backed by db, which may be a *pgxpool.Pool
// or a pgx.Tx. Passing a transaction is how a caller makes several repository
// calls atomic -- see Service.AcceptInvitation.
func NewRepository(db database.DB) *Repository {
	return &Repository{db: db}
}

// sessionTouchInterval throttles writes to sessions.last_used_at. Updating it on
// literally every authenticated request would make each read of a session a row
// rewrite, and the resulting WAL traffic and index churn buys nothing: the field
// only needs to be accurate enough to show a human "last active a few minutes
// ago" in a session list.
//
// It is a SQL literal rather than a parameter because it is a compile-time
// constant, and because pgx has no default codec mapping a Go time.Duration onto
// a Postgres interval -- where a duration does have to cross that boundary, this
// file passes seconds to make_interval() instead.
const sessionTouchInterval = `interval '5 minutes'`

// ---------------------------------------------------------------- users

const userColumns = `id, email, password_hash, full_name, is_superuser, is_active, email_verified_at, created_at, updated_at`

// qualifiedUserColumns is userColumns with every name prefixed by its table. Use
// it in any query that joins users against something else that also has an "id",
// "created_at", or "updated_at" column -- which is nearly everything here.
// Without the prefix Postgres rejects the query as ambiguous.
const qualifiedUserColumns = `users.id, users.email, users.password_hash, users.full_name,
	users.is_superuser, users.is_active, users.email_verified_at, users.created_at, users.updated_at`

// CreateUser inserts a user. passwordHash may be empty for an SSO-only account,
// in which case the column is NULL and password login is impossible for them.
func (r *Repository) CreateUser(ctx context.Context, email, passwordHash, fullName string) (User, error) {
	var hash *string
	if passwordHash != "" {
		hash = &passwordHash
	}

	row := r.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, full_name)
		 VALUES ($1, $2, $3)
		 RETURNING `+userColumns,
		email, hash, fullName,
	)

	u, err := scanUser(row)
	if isUniqueViolation(err, "users_email_key") {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail looks a user up by email. The column is citext, so the
// comparison is case-insensitive without lower() defeating the index.
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
	return scanUserOrNotFound(row, "get user by email")
}

// GetUserByID looks a user up by primary key.
func (r *Repository) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return scanUserOrNotFound(row, "get user by id")
}

// SetSuperuser sets or clears the global superuser flag. There is deliberately
// no HTTP route that reaches this: it is called only from the CLI
// (`server grant-superuser`), so granting the most powerful privilege in the
// system requires database access, not merely a stolen token.
func (r *Repository) SetSuperuser(ctx context.Context, email string, isSuperuser bool) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET is_superuser = $2, updated_at = now()
		 WHERE email = $1
		 RETURNING `+userColumns,
		email, isSuperuser,
	)
	return scanUserOrNotFound(row, "set superuser")
}

// SetUserActive activates or deactivates a user globally.
//
// Deactivation alone does not end their existing sessions -- the caller must also
// revoke them, which Service.SetUserActive does in the same transaction.
// Without that, a deactivated user would keep working until their token expired.
func (r *Repository) SetUserActive(ctx context.Context, userID uuid.UUID, isActive bool) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET is_active = $2, updated_at = now()
		 WHERE id = $1
		 RETURNING `+userColumns,
		userID, isActive,
	)
	return scanUserOrNotFound(row, "set user active")
}

// ListAllUsers returns every user in the installation, newest first. Superuser
// only -- there is no organization filter here, which is precisely why the route that
// reaches it sits behind requireSuperuser.
//
// Keyset pagination on the uuidv7 primary key, as with the audit log: no OFFSET,
// and a stable cursor.
func (r *Repository) ListAllUsers(ctx context.Context, before uuid.UUID, limit int) ([]User, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var beforeArg any
	if before != uuid.Nil {
		beforeArg = before
	}

	rows, err := r.db.Query(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE ($1::uuid IS NULL OR id < $1::uuid)
		 ORDER BY id DESC
		 LIMIT $2`,
		beforeArg, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list all users: %w", err)
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate users: %w", err)
	}
	return out, nil
}

// ListAllOrganizations returns every organization in the installation with its member count.
// Superuser only, for the same reason as ListAllUsers.
func (r *Repository) ListAllOrganizations(ctx context.Context, before uuid.UUID, limit int) ([]OrganizationSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var beforeArg any
	if before != uuid.Nil {
		beforeArg = before
	}

	// NO deleted_at filter, and this is one of only two places in the file that
	// omits it. The staff surface must show DELETED organizations -- flagged, via
	// Organization.DeletedAt -- because a deleted organization 404s for its own owners, so
	// somebody outside it has to be able to find one in order to restore it. An
	// invisible deleted organization is an unrestorable one.
	rows, err := r.db.Query(ctx,
		`SELECT t.id, t.slug, t.name, t.deleted_at, t.created_at, t.updated_at,
		        count(m.id) AS member_count
		 FROM organizations t
		 LEFT JOIN memberships m ON m.organization_id = t.id
		 WHERE ($1::uuid IS NULL OR t.id < $1::uuid)
		 GROUP BY t.id
		 ORDER BY t.id DESC
		 LIMIT $2`,
		beforeArg, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list all organizations: %w", err)
	}
	defer rows.Close()

	out := []OrganizationSummary{}
	for rows.Next() {
		var ts OrganizationSummary
		if err := rows.Scan(
			&ts.Organization.ID, &ts.Organization.Slug, &ts.Organization.Name, &ts.Organization.DeletedAt,
			&ts.Organization.CreatedAt, &ts.Organization.UpdatedAt, &ts.MemberCount,
		); err != nil {
			return nil, fmt.Errorf("identity: scan organization summary: %w", err)
		}
		out = append(out, ts)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate organizations: %w", err)
	}
	return out, nil
}

// UpdateOrganization renames an organization.
//
// The NAME is all that changes. The SLUG is immutable, and deliberately so: it is
// in every URL, bookmark, saved API call, and webhook configuration your customers
// have. Changing it breaks every one of them, silently. A slug is an identifier;
// the name is the label, and the label is what people actually want to fix.
func (r *Repository) UpdateOrganization(ctx context.Context, organizationID uuid.UUID, name string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE organizations SET name = $2, updated_at = now()
		 WHERE id = $1 AND `+liveOrganization+`
		 RETURNING `+organizationColumns,
		organizationID, name,
	)

	t, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: update organization: %w", err)
	}
	return t, nil
}

// SoftDeleteOrganization marks an organization deleted. Not one row is destroyed: every
// membership, role, and audit entry stays exactly where it was, so the organization can
// be restored whole.
//
// The effect is immediate and total. Because every other query in this file
// filters `deleted_at IS NULL`, the organization now 404s for EVERYONE, its owners
// included, and vanishes from "my organizations".
//
// It also releases the slug: the unique index covers live organizations only, so
// somebody else may now claim it. That is what makes restore fallible -- see
// RestoreOrganization.
func (r *Repository) SoftDeleteOrganization(ctx context.Context, organizationID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE organizations SET deleted_at = now(), updated_at = now()
		 WHERE id = $1 AND `+liveOrganization,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf("identity: soft delete organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound // already deleted, or never existed
	}
	return nil
}

// RestoreOrganization brings a soft-deleted organization back, under the given slug.
//
// This is the SECOND query that ignores the deleted_at filter, and it must: it is
// the only way back.
//
// The slug is a parameter rather than simply being the one it had, because
// deletion released it and somebody may have taken it since. If the slug is in
// use by a live organization, the partial unique index rejects this and the caller gets
// ErrSlugTaken -- they must pick another. Restore is always possible; it cannot
// always give you your old URL back.
func (r *Repository) RestoreOrganization(ctx context.Context, organizationID uuid.UUID, slug string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE organizations SET deleted_at = NULL, slug = $2, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NOT NULL
		 RETURNING `+organizationColumns,
		organizationID, slug,
	)

	t, err := scanOrganization(row)
	if isUniqueViolation(err, "organizations_live_slug_idx") {
		return Organization{}, ErrSlugTaken
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound // not deleted, or no such organization
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: restore organization: %w", err)
	}
	return t, nil
}

// GetDeletedOrganization fetches a soft-deleted organization by id, for the restore flow.
func (r *Repository) GetDeletedOrganization(ctx context.Context, organizationID uuid.UUID) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+organizationColumns+` FROM organizations WHERE id = $1 AND deleted_at IS NOT NULL`,
		organizationID,
	)

	t, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: get deleted organization: %w", err)
	}
	return t, nil
}

// UpdateUserPassword replaces a user's password hash. The caller is responsible
// for also revoking the user's sessions -- see Service.ChangePassword, which
// does both in one transaction.
func (r *Repository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`,
		userID, passwordHash,
	)
	if err != nil {
		return fmt.Errorf("identity: update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- organizations

const organizationColumns = `id, slug, name, deleted_at, created_at, updated_at`

// THE SOFT-DELETE RULE, and it is a footgun of exactly the same class as organization
// scoping: every read of an organization must filter `deleted_at IS NULL`. A deleted
// organization is invisible to EVERYONE, including its owners -- that is what makes the
// deletion meaningful.
//
// The two exceptions are deliberate and both belong to the superuser: listing
// deleted organizations (so somebody can find one to restore), and restoring one. They
// are the only queries in this file that omit the filter, and each says so.
const liveOrganization = `deleted_at IS NULL`

// CreateOrganization inserts an organization. It does not create a membership: use
// Service.CreateOrganization, which makes the creator the owner in the same
// transaction, or you will produce an organization nobody can administer.
func (r *Repository) CreateOrganization(ctx context.Context, slug, name string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO organizations (slug, name) VALUES ($1, $2) RETURNING `+organizationColumns,
		slug, name,
	)

	t, err := scanOrganization(row)
	// The constraint is a PARTIAL unique index over live organizations only (see 00008),
	// not the plain UNIQUE it once was -- which is what lets a deleted organization's slug
	// be claimed by somebody else.
	if isUniqueViolation(err, "organizations_live_slug_idx") {
		return Organization{}, ErrSlugTaken
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: create organization: %w", err)
	}
	return t, nil
}

// GetOrganizationBySlug resolves the slug in a request path to an organization. It does NOT
// check that the caller may see it -- that is GetMembership's job, and the
// organization middleware always calls both.
func (r *Repository) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+organizationColumns+` FROM organizations WHERE slug = $1 AND `+liveOrganization, slug)
	t, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: get organization by slug: %w", err)
	}
	return t, nil
}

// GetOrganizationByID looks an organization up by primary key. Callers must already have
// established that the user may see it -- this method performs no authorization.
func (r *Repository) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+organizationColumns+` FROM organizations WHERE id = $1 AND `+liveOrganization, id)
	t, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: get organization by id: %w", err)
	}
	return t, nil
}

// LockOrganization takes a row-level exclusive lock on the organization, held until the
// surrounding transaction ends. It must be called inside a transaction.
//
// Every mutation of an organization's membership set takes this lock first, which
// serialises them against each other. Without it, the last-owner guard is a
// check-then-act race: two admins concurrently demoting one of the final two
// owners would each see a count of two, each conclude their demotion is safe,
// and between them leave the organization with no owner at all.
//
// The lock is per-organization, so it does not serialise unrelated organizations.
func (r *Repository) LockOrganization(ctx context.Context, organizationID uuid.UUID) error {
	var id uuid.UUID
	err := r.db.QueryRow(ctx,
		`SELECT id FROM organizations WHERE id = $1 AND `+liveOrganization+` FOR UPDATE`, organizationID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("identity: lock organization: %w", err)
	}
	return nil
}

// ListOrganizationsForUser returns every organization the user belongs to, with the roles
// they hold in each. This is the "switch organization" menu.
//
// One query with a LEFT JOIN through membership_roles, folded back in Go, rather
// than a roles query per organization -- the classic N+1.
func (r *Repository) ListOrganizationsForUser(ctx context.Context, userID uuid.UUID) ([]OrganizationMembership, error) {
	rows, err := r.db.Query(ctx,
		`SELECT t.id, t.slug, t.name, t.created_at, t.updated_at,
		        `+roleColumns+`, rp.permission
		 FROM organizations t
		 JOIN memberships m            ON m.organization_id = t.id
		 LEFT JOIN membership_roles mr ON mr.membership_id = m.id
		 LEFT JOIN roles r             ON r.id = mr.role_id
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE m.user_id = $1 AND t.`+liveOrganization+`
		 ORDER BY t.name, r.is_system DESC, r.key`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list organizations for user: %w", err)
	}
	defer rows.Close()

	// The join fans out to one row per (organization, role, permission); fold it back.
	byOrganization := map[uuid.UUID]*OrganizationMembership{}
	roleByOrganization := map[uuid.UUID]map[uuid.UUID]*Role{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			t                          Organization
			roleID, roleOrganizationID *uuid.UUID
			roleKey, roleName          *string
			isSystem                   *bool
			rCreated, rUpdated         *time.Time
			perm                       *Permission
		)
		if err := rows.Scan(
			&t.ID, &t.Slug, &t.Name, &t.CreatedAt, &t.UpdatedAt,
			&roleID, &roleOrganizationID, &roleKey, &roleName, &isSystem, &rCreated, &rUpdated, &perm,
		); err != nil {
			return nil, fmt.Errorf("identity: scan organization membership: %w", err)
		}

		if _, seen := byOrganization[t.ID]; !seen {
			byOrganization[t.ID] = &OrganizationMembership{Organization: t}
			roleByOrganization[t.ID] = map[uuid.UUID]*Role{}
			order = append(order, t.ID)
		}
		if roleID == nil {
			continue
		}

		role, seenRole := roleByOrganization[t.ID][*roleID]
		if !seenRole {
			role = &Role{
				ID: *roleID, OrganizationID: roleOrganizationID, Key: *roleKey, Name: *roleName,
				IsSystem: *isSystem, Permissions: PermissionSet{},
				CreatedAt: *rCreated, UpdatedAt: *rUpdated,
			}
			roleByOrganization[t.ID][*roleID] = role
		}
		if perm != nil {
			role.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate organizations for user: %w", err)
	}

	out := make([]OrganizationMembership, 0, len(order))
	for _, organizationID := range order {
		tm := byOrganization[organizationID]
		for _, role := range roleByOrganization[organizationID] {
			tm.Roles = append(tm.Roles, *role)
		}
		sortRoles(tm.Roles)
		out = append(out, *tm)
	}
	return out, nil
}

// ---------------------------------------------------------------- memberships

const membershipColumns = `id, user_id, organization_id, created_at, updated_at`

// CreateMembership adds a user to an organization. It grants NO roles -- the caller must
// follow it with SetMembershipRoles, in the same transaction.
//
// The two are separate because a membership's roles are now a set, not a column.
// The service never leaves a member with zero roles (see ErrNoRoles): a member who
// can do nothing and see nothing is a mistake, not an intent.
func (r *Repository) CreateMembership(ctx context.Context, userID, organizationID uuid.UUID) (Membership, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO memberships (user_id, organization_id)
		 VALUES ($1, $2)
		 RETURNING `+membershipColumns,
		userID, organizationID,
	)

	m, err := scanMembership(row)
	if isUniqueViolation(err, "memberships_user_id_organization_id_key") {
		return Membership{}, ErrAlreadyMember
	}
	if err != nil {
		return Membership{}, fmt.Errorf("identity: create membership: %w", err)
	}
	return m, nil
}

// GetMembership returns the user's membership in the organization, or ErrNotFound if
// they have none. This single call is the authorization check that every
// organization-scoped request passes through.
func (r *Repository) GetMembership(ctx context.Context, userID, organizationID uuid.UUID) (Membership, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+membershipColumns+` FROM memberships WHERE user_id = $1 AND organization_id = $2`,
		userID, organizationID,
	)

	m, err := scanMembership(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("identity: get membership: %w", err)
	}
	return m, nil
}

// ListMembers returns the organization's members with their user details, the roles
// each holds, and the union of those roles' permissions.
//
// One query with a LEFT JOIN through membership_roles, folded back in Go. A roles
// query per member would be the classic N+1: on an organization with a few hundred
// members that is the difference between one round trip and several hundred.
func (r *Repository) ListMembers(ctx context.Context, organizationID uuid.UUID) ([]Member, error) {
	rows, err := r.db.Query(ctx,
		`SELECT u.id, u.email, u.full_name, m.created_at,
		        `+roleColumns+`, rp.permission
		 FROM memberships m
		 JOIN users u                  ON u.id = m.user_id
		 LEFT JOIN membership_roles mr ON mr.membership_id = m.id
		 LEFT JOIN roles r             ON r.id = mr.role_id
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE m.organization_id = $1
		 ORDER BY u.email, r.is_system DESC, r.key`,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list members: %w", err)
	}
	defer rows.Close()

	byUser := map[uuid.UUID]*Member{}
	roleByUser := map[uuid.UUID]map[uuid.UUID]*Role{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			userID                     uuid.UUID
			email, fullName            string
			joinedAt                   time.Time
			roleID, roleOrganizationID *uuid.UUID
			roleKey, roleName          *string
			isSystem                   *bool
			rCreated, rUpdated         *time.Time
			perm                       *Permission
		)
		if err := rows.Scan(
			&userID, &email, &fullName, &joinedAt,
			&roleID, &roleOrganizationID, &roleKey, &roleName, &isSystem, &rCreated, &rUpdated, &perm,
		); err != nil {
			return nil, fmt.Errorf("identity: scan member: %w", err)
		}

		member, seen := byUser[userID]
		if !seen {
			member = &Member{
				UserID: userID, Email: email, FullName: fullName,
				JoinedAt: joinedAt, Permissions: PermissionSet{},
			}
			byUser[userID] = member
			roleByUser[userID] = map[uuid.UUID]*Role{}
			order = append(order, userID)
		}
		if roleID == nil {
			continue // a member holding no roles
		}

		role, seenRole := roleByUser[userID][*roleID]
		if !seenRole {
			role = &Role{
				ID: *roleID, OrganizationID: roleOrganizationID, Key: *roleKey, Name: *roleName,
				IsSystem: *isSystem, Permissions: PermissionSet{},
				CreatedAt: *rCreated, UpdatedAt: *rUpdated,
			}
			roleByUser[userID][*roleID] = role
		}
		if perm != nil {
			role.Permissions[*perm] = struct{}{}
			// The member's own set is the union across every role they hold --
			// which is the whole point of allowing more than one.
			member.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate members: %w", err)
	}

	out := make([]Member, 0, len(order))
	for _, userID := range order {
		m := byUser[userID]
		for _, role := range roleByUser[userID] {
			m.Roles = append(m.Roles, *role)
		}
		sortRoles(m.Roles)
		out = append(out, *m)
	}
	return out, nil
}

// DeleteMembership removes a user from an organization. organization_id is in the WHERE clause
// so that an admin of organization A cannot, by supplying a user ID they happen to
// know, remove that user from organization B.
//
// membership_roles cascades off the membership, so their role assignments go with
// them.
func (r *Repository) DeleteMembership(ctx context.Context, organizationID, userID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2`,
		organizationID, userID,
	)
	if err != nil {
		return fmt.Errorf("identity: delete membership: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountOwners now lives in roles_repository.go: "an owner" is no longer a column
// on memberships but a member holding the system owner role.

// sortRoles orders roles for display: system roles first (owner, admin, member as
// the reader expects), then custom ones alphabetically. Map iteration in Go is
// randomised, so without this the same member's roles would come back in a
// different order on every request.
func sortRoles(roles []Role) {
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].IsSystem != roles[j].IsSystem {
			return roles[i].IsSystem // system roles first
		}
		return roles[i].Key < roles[j].Key
	})
}

// ---------------------------------------------------------------- sessions

// CreateSession stores a new session. tokenHash is the SHA-256 of the plaintext
// token; the plaintext itself is never given to this layer.
func (r *Repository) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	tokenHash []byte,
	expiresAt time.Time,
	userAgent, ipAddress string,
) (Session, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at`,
		userID, tokenHash, expiresAt, userAgent, parseIP(ipAddress),
	)

	s, err := scanSession(row)
	if err != nil {
		return Session{}, fmt.Errorf("identity: create session: %w", err)
	}
	s.TokenHash = tokenHash
	return s, nil
}

// AuthenticateSession resolves a session token hash to the user it belongs to,
// in a single round trip, and refreshes last_used_at at most once every
// sessionTouchInterval.
//
// The validity rules live in SQL rather than in Go on purpose: a session is
// usable only if it is unrevoked, unexpired, and belongs to an active user, and
// putting all three in the WHERE clause means no caller can forget one.
//
// It returns ErrUnauthenticated for every failure -- unknown token, revoked,
// expired, deactivated user -- because the caller has no legitimate use for the
// distinction and an attacker does.
func (r *Repository) AuthenticateSession(ctx context.Context, tokenHash []byte) (User, Session, error) {
	// The data-modifying CTE runs to completion whether or not the outer SELECT
	// reads it, so the touch happens even for the (common) case where the
	// throttle window means no row is updated.
	row := r.db.QueryRow(ctx,
		`WITH live AS (
		     SELECT id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at
		     FROM sessions
		     WHERE token_hash = $1
		       AND revoked_at IS NULL
		       AND expires_at > now()
		 ), touched AS (
		     UPDATE sessions SET last_used_at = now()
		     -- Qualify both sides: an unadorned "id" here is ambiguous between
		     -- sessions.id and live.id, and Postgres rejects the statement.
		     WHERE sessions.id IN (SELECT live.id FROM live)
		       AND (sessions.last_used_at IS NULL
		            OR sessions.last_used_at < now() - `+sessionTouchInterval+`)
		 )
		 SELECT `+qualifiedUserColumns+`,
		        live.id, live.user_id, live.expires_at, live.revoked_at,
		        live.user_agent, live.ip_address, live.last_used_at, live.created_at
		 FROM live
		 JOIN users ON users.id = live.user_id
		 WHERE users.is_active`,
		tokenHash,
	)

	var u User
	var hash *string
	var s Session
	var ip *netip.Addr
	err := row.Scan(
		&u.ID, &u.Email, &hash, &u.FullName, &u.IsSuperuser, &u.IsActive, &u.EmailVerifiedAt,
		&u.CreatedAt, &u.UpdatedAt,
		&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, Session{}, ErrUnauthenticated
	}
	if err != nil {
		return User{}, Session{}, fmt.Errorf("identity: authenticate session: %w", err)
	}
	if hash != nil {
		u.PasswordHash = *hash
	}
	if ip != nil {
		s.IPAddress = ip.String()
	}
	s.TokenHash = tokenHash
	return u, s, nil
}

// RevokeSession marks one session dead. It is idempotent: revoking an already
// revoked or unknown token is not an error, because logout must always appear
// to succeed.
func (r *Repository) RevokeSession(ctx context.Context, tokenHash []byte) error {
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	return nil
}

// RevokeUserSessions kills every live session a user has. This is the payoff of
// database-backed sessions over JWTs: a password change or a deactivation takes
// effect on the very next request, everywhere, instead of after the token's TTL.
func (r *Repository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListUserSessions returns a user's live sessions, newest first -- the "you are
// signed in on these devices" screen. id is a uuidv7, so ordering by it is
// ordering by creation time.
func (r *Repository) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at
		 FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY id DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list sessions: %w", err)
	}
	defer rows.Close()

	out := []Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate sessions: %w", err)
	}
	return out, nil
}

// DeleteDeadSessions permanently removes sessions that expired or were revoked
// more than retain ago. Sessions are the one table here that grows without
// bound, so something must prune it -- cmd/server runs this on a ticker.
func (r *Repository) DeleteDeadSessions(ctx context.Context, retain time.Duration) (int64, error) {
	// make_interval(secs => ...) is how a Go duration reaches Postgres as an
	// interval: pgx would not know what to do with a time.Duration directly.
	tag, err := r.db.Exec(ctx,
		`DELETE FROM sessions
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (revoked_at IS NOT NULL AND revoked_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- password resets

// CreatePasswordReset stores a reset token. The plaintext lives in the email and
// nowhere else; this layer only ever sees the digest.
func (r *Repository) CreatePasswordReset(
	ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time, ip, userAgent string,
) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO password_resets (user_id, token_hash, expires_at, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5)`,
		userID, tokenHash, expiresAt, parseIP(ip), userAgent,
	)
	if err != nil {
		return fmt.Errorf("identity: create password reset: %w", err)
	}
	return nil
}

// ConsumePasswordReset spends a reset token and returns whose it was.
//
// The whole check is in the WHERE clause -- unspent, unexpired -- and the UPDATE is
// what claims it. That is not a stylistic choice: a check-then-write in Go would
// let two concurrent requests both read an unused token, both conclude it was
// valid, and both reset the password. Here exactly one UPDATE affects a row, and
// the loser gets ErrInvalidToken.
func (r *Repository) ConsumePasswordReset(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var userID uuid.UUID
	err := r.db.QueryRow(ctx,
		`UPDATE password_resets SET used_at = now()
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()
		 RETURNING user_id`,
		tokenHash,
	).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown, already spent, or expired. The caller cannot tell which, and has
		// no legitimate need to.
		return uuid.Nil, ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity: consume password reset: %w", err)
	}
	return userID, nil
}

// InvalidatePasswordResets spends every outstanding reset token for a user.
//
// Called when a new one is issued (so the old link stops working -- what you want
// if the first went astray), and again when a reset completes (so a second
// outstanding link cannot be used to change the password straight back).
func (r *Repository) InvalidatePasswordResets(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE password_resets SET used_at = now()
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("identity: invalidate password resets: %w", err)
	}
	return nil
}

// DeleteDeadPasswordResets prunes spent and expired rows. Run on the same ticker
// as the session reaper.
func (r *Repository) DeleteDeadPasswordResets(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM password_resets
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (used_at IS NOT NULL AND used_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead password resets: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- invitations

// invitationSelect joins each invitation to the role it offers. An invitation now
// points at a role row rather than carrying a role string, so an organization can invite
// somebody straight into one of its own custom roles.
const invitationSelect = `
	SELECT i.id, i.organization_id, i.email, i.invited_by, i.expires_at,
	       i.accepted_at, i.revoked_at, i.created_at,
	       r.id, r.organization_id, r.key, r.name, r.is_system, r.created_at, r.updated_at,
	       rp.permission
	FROM invitations i
	JOIN roles r                  ON r.id = i.role_id
	LEFT JOIN role_permissions rp ON rp.role_id = r.id`

// CreateInvitation stores a pending invitation offering the given role.
func (r *Repository) CreateInvitation(
	ctx context.Context,
	organizationID uuid.UUID,
	email string,
	roleID uuid.UUID,
	invitedBy uuid.UUID,
	tokenHash []byte,
	expiresAt time.Time,
) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx,
		`INSERT INTO invitations (organization_id, email, role_id, invited_by, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id`,
		organizationID, email, roleID, invitedBy, tokenHash, expiresAt,
	).Scan(&id)

	if isUniqueViolation(err, "invitations_pending_email_idx") {
		// A live invitation for this email already exists. The service revokes the
		// old one first, so reaching here means a genuine race.
		return uuid.Nil, ErrAlreadyMember
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity: create invitation: %w", err)
	}
	return id, nil
}

// GetInvitation returns one invitation by id, with the role it offers.
func (r *Repository) GetInvitation(ctx context.Context, id uuid.UUID) (Invitation, error) {
	rows, err := r.db.Query(ctx, invitationSelect+` WHERE i.id = $1`, id)
	if err != nil {
		return Invitation{}, fmt.Errorf("identity: get invitation: %w", err)
	}
	defer rows.Close()

	invitations, err := collectInvitations(rows)
	if err != nil {
		return Invitation{}, err
	}
	if len(invitations) == 0 {
		return Invitation{}, ErrNotFound
	}
	return invitations[0], nil
}

// GetInvitationByTokenHash resolves an invitation link. It returns the row even
// if it is expired or spent; the service decides, via Invitation.Pending,
// whether it may still be accepted.
func (r *Repository) GetInvitationByTokenHash(ctx context.Context, tokenHash []byte) (Invitation, error) {
	rows, err := r.db.Query(ctx, invitationSelect+` WHERE i.token_hash = $1`, tokenHash)
	if err != nil {
		return Invitation{}, fmt.Errorf("identity: get invitation by token: %w", err)
	}
	defer rows.Close()

	invitations, err := collectInvitations(rows)
	if err != nil {
		return Invitation{}, err
	}
	if len(invitations) == 0 {
		return Invitation{}, ErrInvitationInvalid
	}
	inv := invitations[0]
	inv.TokenHash = tokenHash
	return inv, nil
}

// collectInvitations folds the invitation x permission fan-out produced by the
// LEFT JOIN back into one Invitation per id, each with its role fully populated.
func collectInvitations(rows pgx.Rows) ([]Invitation, error) {
	byID := map[uuid.UUID]*Invitation{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			inv                Invitation
			role               Role
			roleOrganizationID *uuid.UUID
			rCreated, rUpdated time.Time
			perm               *Permission
		)
		if err := rows.Scan(
			&inv.ID, &inv.OrganizationID, &inv.Email, &inv.InvitedBy, &inv.ExpiresAt,
			&inv.AcceptedAt, &inv.RevokedAt, &inv.CreatedAt,
			&role.ID, &roleOrganizationID, &role.Key, &role.Name, &role.IsSystem, &rCreated, &rUpdated,
			&perm,
		); err != nil {
			return nil, fmt.Errorf("identity: scan invitation: %w", err)
		}

		existing, seen := byID[inv.ID]
		if !seen {
			role.OrganizationID = roleOrganizationID
			role.CreatedAt, role.UpdatedAt = rCreated, rUpdated
			role.Permissions = PermissionSet{}
			inv.Role = role

			byID[inv.ID] = &inv
			order = append(order, inv.ID)
			existing = &inv
		}
		if perm != nil {
			existing.Role.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate invitations: %w", err)
	}

	out := make([]Invitation, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// ListPendingInvitations returns the organization's outstanding invitations, each with
// the role it offers.
func (r *Repository) ListPendingInvitations(ctx context.Context, organizationID uuid.UUID) ([]Invitation, error) {
	rows, err := r.db.Query(ctx,
		invitationSelect+`
		 WHERE i.organization_id = $1
		   AND i.accepted_at IS NULL
		   AND i.revoked_at IS NULL
		   AND i.expires_at > now()
		 ORDER BY i.id DESC`,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list invitations: %w", err)
	}
	defer rows.Close()

	return collectInvitations(rows)
}

// AcceptInvitation marks an invitation spent, but only if it is still pending.
// The guard is in the WHERE clause, not in Go, so that two concurrent accepts of
// the same link cannot both pass a check-then-write race: exactly one will
// report a row affected.
func (r *Repository) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE invitations SET accepted_at = now()
		 WHERE id = $1
		   AND accepted_at IS NULL
		   AND revoked_at IS NULL
		   AND expires_at > now()`,
		id,
	)
	if err != nil {
		return fmt.Errorf("identity: accept invitation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvitationInvalid
	}
	return nil
}

// RevokeInvitation withdraws a pending invitation. organizationID is in the WHERE
// clause so an admin cannot revoke another organization's invitation by id.
func (r *Repository) RevokeInvitation(ctx context.Context, organizationID, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE invitations SET revoked_at = now()
		 WHERE id = $1 AND organization_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
		id, organizationID,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke invitation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokePendingInvitationFor withdraws any live invitation for an email in a
// organization. The service calls it before issuing a new one, so that re-inviting
// somebody replaces their old link instead of colliding with the partial unique
// index on (organization_id, email).
func (r *Repository) RevokePendingInvitationFor(ctx context.Context, organizationID uuid.UUID, email string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE invitations SET revoked_at = now()
		 WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
		organizationID, email,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke pending invitation: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- scanning

// row is the common ground between pgx.Row (single) and pgx.Rows (iterated), so
// one scan function serves both a QueryRow and a loop over Query.
type row interface {
	Scan(dest ...any) error
}

func scanUser(r row) (User, error) {
	var u User
	var hash *string // NULL for SSO-only accounts
	err := r.Scan(&u.ID, &u.Email, &hash, &u.FullName, &u.IsSuperuser, &u.IsActive,
		&u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	if hash != nil {
		u.PasswordHash = *hash
	}
	return u, nil
}

func scanUserOrNotFound(r row, op string) (User, error) {
	u, err := scanUser(r)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: %s: %w", op, err)
	}
	return u, nil
}

func scanOrganization(r row) (Organization, error) {
	var t Organization
	err := r.Scan(&t.ID, &t.Slug, &t.Name, &t.DeletedAt, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func scanMembership(r row) (Membership, error) {
	var m Membership
	err := r.Scan(&m.ID, &m.UserID, &m.OrganizationID, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

func scanSession(r row) (Session, error) {
	var s Session
	var ip *netip.Addr // pgx maps a nullable inet onto this; NULL yields nil
	err := r.Scan(
		&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt,
		&s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
	)
	if err != nil {
		return Session{}, err
	}
	if ip != nil {
		s.IPAddress = ip.String()
	}
	return s, nil
}

// ---------------------------------------------------------------- helpers

// parseIP converts a client IP string into the *netip.Addr that pgx encodes into
// an inet column, or nil for NULL.
//
// A malformed or absent address becomes NULL rather than an error: we are not
// going to refuse somebody's login because a proxy in front of us sent a header
// we could not parse.
func parseIP(s string) *netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}

// isUniqueViolation reports whether err is a Postgres unique-constraint failure
// on the named constraint. Matching the constraint name -- rather than just the
// 23505 SQLSTATE -- means adding a second unique index to a table later cannot
// silently turn its violation into the wrong error for the user.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// isForeignKeyViolation reports whether err is a Postgres referential-integrity
// failure on the named constraint.
//
// BOTH SQLSTATEs are checked, and the distinction is easy to get wrong:
//
//	23503 foreign_key_violation -- inserting a row that points at nothing, e.g.
//	      granting a permission that is not in the catalog.
//	23001 restrict_violation    -- deleting a row that something still points at,
//	      when the constraint is ON DELETE RESTRICT (as opposed to NO ACTION,
//	      which reports 23503 instead).
//
// Matching only 23503 silently misses every RESTRICT failure, and the raw
// Postgres error escapes to the caller as a 500.
//
// Two of these are load-bearing rather than incidental:
//
//   - membership_roles_role_id_fkey (RESTRICT) fires when deleting a role somebody
//     still holds. Better a loud refusal than silently stripping their access.
//   - role_permissions_permission_fkey fires when granting a permission that is
//     not in the catalog -- i.e. one that no code enforces. It is the database
//     itself enforcing "permissions come from code".
func isForeignKeyViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	isFKError := pgErr.Code == "23503" || pgErr.Code == "23001"
	return isFKError && pgErr.ConstraintName == constraint
}

// ---------------------------------------------------------------- email verification

// CreateEmailVerification stores a verification token.
func (r *Repository) CreateEmailVerification(
	ctx context.Context, userID uuid.UUID, email string, tokenHash []byte, expiresAt time.Time,
) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO email_verifications (user_id, email, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		userID, email, tokenHash, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("identity: create email verification: %w", err)
	}
	return nil
}

// ConsumeEmailVerification spends a token and returns whose address it confirms.
//
// Validity is checked and claimed in the one UPDATE, so two concurrent uses of the
// same link cannot both succeed.
func (r *Repository) ConsumeEmailVerification(ctx context.Context, tokenHash []byte) (uuid.UUID, string, error) {
	var userID uuid.UUID
	var email string

	err := r.db.QueryRow(ctx,
		`UPDATE email_verifications SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING user_id, email`,
		tokenHash,
	).Scan(&userID, &email)

	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("identity: consume email verification: %w", err)
	}
	return userID, email, nil
}

// MarkEmailVerified stamps the user's address as confirmed.
//
// The email is in the WHERE clause: a token minted for one address must not verify
// a different one, which is what would happen if the user changed their email
// between requesting the link and clicking it.
func (r *Repository) MarkEmailVerified(ctx context.Context, userID uuid.UUID, email string) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET email_verified_at = now(), updated_at = now()
		 WHERE id = $1 AND email = $2
		 RETURNING `+userColumns,
		userID, email,
	)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// The address changed under the token. Refuse rather than verify the wrong one.
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: mark email verified: %w", err)
	}
	return u, nil
}

// InvalidateEmailVerifications spends every outstanding token for a user, so that
// only the newest link works.
func (r *Repository) InvalidateEmailVerifications(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE email_verifications SET used_at = now()
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("identity: invalidate email verifications: %w", err)
	}
	return nil
}

// DeleteDeadEmailVerifications prunes spent and expired rows.
func (r *Repository) DeleteDeadEmailVerifications(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM email_verifications
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (used_at IS NOT NULL AND used_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead email verifications: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- organization purge

// CountOrganizationsForUser returns how many LIVE organizations the user belongs to. The cap on
// organization creation is checked against it.
func (r *Repository) CountOrganizationsForUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM memberships m
		 JOIN organizations t ON t.id = m.organization_id
		 WHERE m.user_id = $1 AND t.`+liveOrganization,
		userID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("identity: count organizations for user: %w", err)
	}
	return n, nil
}

// PurgeDeletedOrganizations HARD-deletes organizations that were soft-deleted longer than retain
// ago, cascading away every row they own.
//
// This is the right-to-erasure path, and it is the only thing in the application
// that destroys organization data. It cascades into audit_log, so it must announce itself
// to the append-only trigger -- which is why the caller runs it in a transaction
// that sets app.audit_purge.
//
// retain <= 0 means keep forever, which is the default: silently destroying a
// customer's data because a config value had a tidy default is not a decision this
// template makes.
func (r *Repository) PurgeDeletedOrganizations(ctx context.Context, retain time.Duration) (int64, error) {
	if retain <= 0 {
		return 0, nil
	}

	tag, err := r.db.Exec(ctx,
		`DELETE FROM organizations
		 WHERE deleted_at IS NOT NULL
		   AND deleted_at < now() - make_interval(secs => $1)`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: purge deleted organizations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeSessionByID revokes ONE session belonging to a user.
//
// user_id is in the WHERE clause, so a caller cannot revoke somebody else's session
// by guessing its id.
func (r *Repository) RevokeSessionByID(ctx context.Context, userID, sessionID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		sessionID, userID,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke session by id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
