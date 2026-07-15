package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Everything that reads or writes API keys and their frozen permission scope.
//
// The ORGANIZATION-SCOPING RULE applies exactly as it does everywhere else: every
// method that manages a key takes an organizationID and puts it in the WHERE
// clause, so one organization can never see, revoke, or authenticate against
// another's keys even by guessing an id.

// apiKeyColumns is the api_keys row, in a fixed order the scanners below rely on.
const apiKeyColumns = `id, organization_id, name, token_prefix, created_by,
	expires_at, last_used_at, revoked_at, created_at`

// CreateAPIKey inserts a key and its permission scope. It must run in a
// transaction: a key committed without its permissions would authenticate but be
// able to do nothing, and there would be no moment to notice.
func (r *Repository) CreateAPIKey(
	ctx context.Context,
	organizationID uuid.UUID,
	name, tokenPrefix string,
	tokenHash []byte,
	createdBy uuid.UUID,
	perms PermissionSet,
	expiresAt *time.Time,
) (APIKey, error) {
	var k APIKey
	err := r.db.QueryRow(ctx,
		`INSERT INTO api_keys (organization_id, name, token_hash, token_prefix, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+apiKeyColumns,
		organizationID, name, tokenHash, tokenPrefix, createdBy, expiresAt,
	).Scan(&k.ID, &k.OrganizationID, &k.Name, &k.TokenPrefix, &k.CreatedBy,
		&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt)
	if err != nil {
		return APIKey{}, fmt.Errorf("identity: create api key: %w", err)
	}

	for _, p := range perms.Slice() {
		_, err := r.db.Exec(ctx,
			`INSERT INTO api_key_permissions (api_key_id, permission) VALUES ($1, $2)`,
			k.ID, p,
		)
		if isForeignKeyViolation(err, "api_key_permissions_permission_fkey") {
			// Not in the catalog: no code enforces it. The service validates against
			// Catalog first, so reaching here means the database and the binary
			// disagree about what permissions exist.
			return APIKey{}, fmt.Errorf("%w: %q is not a permission this application enforces", ErrValidation, p)
		}
		if err != nil {
			return APIKey{}, fmt.Errorf("identity: grant api key permission %q: %w", p, err)
		}
	}
	k.Permissions = perms
	return k, nil
}

// ListAPIKeys returns an organization's live (non-revoked) keys, each with its
// permission scope. It never returns the token hash -- there is nothing to return,
// since the plaintext was shown once and only the hash was ever stored.
func (r *Repository) ListAPIKeys(ctx context.Context, organizationID uuid.UUID) ([]APIKey, error) {
	rows, err := r.db.Query(ctx,
		`SELECT k.id, k.organization_id, k.name, k.token_prefix, k.created_by,
		        k.expires_at, k.last_used_at, k.revoked_at, k.created_at, kp.permission
		 FROM api_keys k
		 LEFT JOIN api_key_permissions kp ON kp.api_key_id = k.id
		 WHERE k.organization_id = $1 AND k.revoked_at IS NULL
		 ORDER BY k.created_at DESC`,
		organizationID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list api keys: %w", err)
	}
	defer rows.Close()

	return collectAPIKeys(rows)
}

// RevokeAPIKey marks a key dead. organization_id is in the WHERE clause, so this
// cannot revoke another organization's key. It returns the key (for the audit
// entry) or ErrNotFound if there is no live key with that id here.
func (r *Repository) RevokeAPIKey(ctx context.Context, organizationID, id uuid.UUID) (APIKey, error) {
	var k APIKey
	err := r.db.QueryRow(ctx,
		`UPDATE api_keys SET revoked_at = now()
		 WHERE id = $2 AND organization_id = $1 AND revoked_at IS NULL
		 RETURNING `+apiKeyColumns,
		organizationID, id,
	).Scan(&k.ID, &k.OrganizationID, &k.Name, &k.TokenPrefix, &k.CreatedBy,
		&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("identity: revoke api key: %w", err)
	}
	return k, nil
}

// AuthenticateAPIKey resolves a plaintext token's hash to its key, validating that
// the key is live, unexpired, its organization is not soft-deleted, and its
// creating user is still active -- so deactivating a person disables their keys on
// the very next request. It touches last_used_at (throttled), and loads the key's
// permission scope. It returns ErrUnauthenticated when nothing matches, exactly as
// session auth does, so the caller answers 401 rather than leaking which part failed.
func (r *Repository) AuthenticateAPIKey(ctx context.Context, tokenHash []byte) (APIKey, error) {
	var k APIKey
	err := r.db.QueryRow(ctx,
		`WITH live AS (
		     SELECT k.id, k.organization_id, k.name, k.token_prefix, k.created_by,
		            k.expires_at, k.last_used_at, k.revoked_at, k.created_at
		     FROM api_keys k
		     JOIN organizations o ON o.id = k.organization_id AND o.deleted_at IS NULL
		     JOIN users u         ON u.id = k.created_by AND u.is_active
		     WHERE k.token_hash = $1
		       AND k.revoked_at IS NULL
		       AND (k.expires_at IS NULL OR k.expires_at > now())
		 ), touched AS (
		     UPDATE api_keys SET last_used_at = now()
		     WHERE api_keys.id IN (SELECT id FROM live)
		       AND (api_keys.last_used_at IS NULL
		            OR api_keys.last_used_at < now() - `+sessionTouchInterval+`)
		 )
		 SELECT id, organization_id, name, token_prefix, created_by,
		        expires_at, last_used_at, revoked_at, created_at
		 FROM live`,
		tokenHash,
	).Scan(&k.ID, &k.OrganizationID, &k.Name, &k.TokenPrefix, &k.CreatedBy,
		&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrUnauthenticated
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("identity: authenticate api key: %w", err)
	}

	perms, err := r.loadAPIKeyPermissions(ctx, k.ID)
	if err != nil {
		return APIKey{}, err
	}
	k.Permissions = perms
	return k, nil
}

// loadAPIKeyPermissions returns the frozen scope of one key.
func (r *Repository) loadAPIKeyPermissions(ctx context.Context, apiKeyID uuid.UUID) (PermissionSet, error) {
	rows, err := r.db.Query(ctx,
		`SELECT permission FROM api_key_permissions WHERE api_key_id = $1`, apiKeyID)
	if err != nil {
		return nil, fmt.Errorf("identity: load api key permissions: %w", err)
	}
	defer rows.Close()

	set := PermissionSet{}
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("identity: scan api key permission: %w", err)
		}
		set[p] = struct{}{}
	}
	return set, rows.Err()
}

// collectAPIKeys folds the key x permission rows produced by the LEFT JOIN back
// into one APIKey per id, gathering its permissions into a set -- the same
// fan-in that collectRoles does for roles.
func collectAPIKeys(rows pgx.Rows) ([]APIKey, error) {
	byID := map[uuid.UUID]*APIKey{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			k    APIKey
			perm *Permission
		)
		if err := rows.Scan(&k.ID, &k.OrganizationID, &k.Name, &k.TokenPrefix, &k.CreatedBy,
			&k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt, &perm); err != nil {
			return nil, fmt.Errorf("identity: scan api key: %w", err)
		}

		existing, seen := byID[k.ID]
		if !seen {
			k.Permissions = PermissionSet{}
			byID[k.ID] = &k
			existing = &k
			order = append(order, k.ID)
		}
		if perm != nil {
			existing.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate api keys: %w", err)
	}

	out := make([]APIKey, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}
