package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// Permission is a single thing a caller may be allowed to do, named
// "resource.action".
//
// THE CATALOG BELOW IS THE SOURCE OF TRUTH. Permissions come from code; roles
// are data.
//
// A permission means something only because some line of Go enforces it -- a
// route wrapped in requirePermission, or a check in a service method. If users
// could invent permission names at runtime, they could create "billing.refund",
// assign it to a role, and see it rendered with a checkbox in the UI, while it
// enforced precisely nothing. It would look like it worked and grant zero.
//
// So: adding a permission is a code change (add the constant, add it to Catalog,
// guard something with it). What customers configure at runtime is which
// permissions each of their roles bundles -- see roles.go.
type Permission string

// The naming convention is <resource>.<action>, with CRUD verbs, and it has no
// exceptions. Adding a resource means adding queues.create / queues.read /
// queues.update / queues.delete -- a developer never invents a verb, and a
// customer building a role never has to guess what a word like "manage" covers.
//
// Note what is NOT here: organization.create, and users.create. Every permission in
// this catalog is evaluated INSIDE an organization -- requirePermission runs after
// requireOrganization, against the roles you hold there. Creating an organization, or
// registering, happens when you are not in one yet, so there is nothing to hold a
// permission against. Those routes are guarded by authentication alone.
const (
	// Organization. There is no organization.create; see above.
	PermOrganizationRead   Permission = "organization.read"
	PermOrganizationUpdate Permission = "organization.update" // the name; the slug is immutable
	PermOrganizationDelete Permission = "organization.delete" // soft delete -- restorable by a superuser

	// Members. A membership is created by accepting an invitation, not by an
	// admin conjuring one, so there is no members.create.
	PermMembersRead   Permission = "members.read"
	PermMembersUpdate Permission = "members.update" // change which roles they hold
	PermMembersDelete Permission = "members.delete" // remove them from the organization

	// Invitations. "Inviting somebody" is creating an invitation, and revoking one
	// is deleting it -- naming them so makes them ordinary.
	PermInvitationsRead   Permission = "invitations.read"
	PermInvitationsCreate Permission = "invitations.create"
	PermInvitationsDelete Permission = "invitations.delete"

	// Roles. Split into three, where a single roles.manage used to lump them
	// together -- so you can now grant "may edit roles but not delete them".
	PermRolesRead   Permission = "roles.read"
	PermRolesCreate Permission = "roles.create"
	PermRolesUpdate Permission = "roles.update"
	PermRolesDelete Permission = "roles.delete"

	// Audit.
	PermAuditRead Permission = "audit.read"

	// API keys. Programmatic, org-scoped credentials. Managing them is an
	// administrative act, so they are split create/read/delete like roles.
	PermAPIKeysRead   Permission = "apikeys.read"
	PermAPIKeysCreate Permission = "apikeys.create"
	PermAPIKeysDelete Permission = "apikeys.delete"
)

// CatalogEntry is one permission plus the description shown in a role editor.
type CatalogEntry struct {
	Key         Permission `json:"key"`
	Description string     `json:"description"`
}

// Catalog is every permission this application enforces. It is what
// GET /api/v1/permissions returns, so a UI can render its checkbox list, and
// what SyncPermissions writes into the database.
//
// When you guard a new route, add its permission here. If you do not, the
// foreign key from role_permissions will reject any attempt to grant it -- which
// is the intended failure: loud, at the point of use, rather than a permission
// that silently does nothing.
var Catalog = []CatalogEntry{
	{PermOrganizationRead, "View the organization and its settings"},
	{PermOrganizationUpdate, "Rename the organization"},
	{PermOrganizationDelete, "Delete the organization"},

	{PermMembersRead, "View the organization's members"},
	{PermMembersUpdate, "Change which roles a member holds"},
	{PermMembersDelete, "Remove members from the organization"},

	{PermInvitationsRead, "View pending invitations"},
	{PermInvitationsCreate, "Invite people to the organization"},
	{PermInvitationsDelete, "Revoke a pending invitation"},

	{PermRolesRead, "View the organization's roles"},
	{PermRolesCreate, "Create custom roles"},
	{PermRolesUpdate, "Edit custom roles"},
	{PermRolesDelete, "Delete custom roles"},

	{PermAuditRead, "Read the organization's audit log"},

	{PermAPIKeysRead, "View the organization's API keys"},
	{PermAPIKeysCreate, "Create API keys"},
	{PermAPIKeysDelete, "Revoke API keys"},
}

// Valid reports whether p is a permission this application actually enforces.
// Always call it on a permission that arrived in a request body, before it
// reaches the database -- the FK would catch it too, but a 400 beats a 500.
func (p Permission) Valid() bool {
	return slices.ContainsFunc(Catalog, func(e CatalogEntry) bool { return e.Key == p })
}

// PermissionSet is what a caller may do inside one organization: the union of the
// permissions granted by every role they hold there.
//
// It is a set, not a ladder. The old model ranked owner > admin > member and
// asked "are you at least an admin?"; that could never express "may manage
// billing but not members", because authority was one-dimensional. A set has no
// ordering, and every check is simply "is this permission in it?".
type PermissionSet map[Permission]struct{}

// NewPermissionSet builds a set from a slice.
func NewPermissionSet(perms ...Permission) PermissionSet {
	set := make(PermissionSet, len(perms))
	for _, p := range perms {
		set[p] = struct{}{}
	}
	return set
}

// AllPermissions returns a set containing everything in the catalog. This is what
// a superuser holds in every organization.
func AllPermissions() PermissionSet {
	set := make(PermissionSet, len(Catalog))
	for _, e := range Catalog {
		set[e.Key] = struct{}{}
	}
	return set
}

// Has reports whether the set contains p. This is the single question every
// authorization check in the application asks.
func (s PermissionSet) Has(p Permission) bool {
	_, ok := s[p]
	return ok
}

// Superset reports whether s contains every permission in other.
//
// THIS IS THE ESCALATION GUARD. Before anyone creates a role, edits a role's
// permissions, or assigns a role to a member, the service checks that the actor's
// own permission set is a superset of the permissions being handed out.
//
// Without it, RBAC is self-defeating: an admin holding roles.manage would simply
// create a role carrying organization.delete, assign it to themselves, and have escaped
// every limit you placed on them. The same one rule also stops them assigning the
// system "owner" role, since owner carries permissions they do not hold -- no
// special-casing required.
func (s PermissionSet) Superset(other PermissionSet) bool {
	for p := range other {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

// Missing returns the permissions in other that s lacks, sorted -- so a refusal
// can tell the caller exactly which permissions they tried to grant beyond their
// own authority, instead of a bare "forbidden".
func (s PermissionSet) Missing(other PermissionSet) []Permission {
	var out []Permission
	for p := range other {
		if !s.Has(p) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Slice returns the set's permissions, sorted, for JSON responses and tests.
func (s PermissionSet) Slice() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// MarshalJSON renders the set as a sorted array rather than as an object with
// empty values, which is what a client actually wants to see.
func (s PermissionSet) MarshalJSON() ([]byte, error) {
	perms := s.Slice()
	if perms == nil {
		perms = []Permission{}
	}
	return json.Marshal(perms)
}

// SyncPermissions reconciles the database catalog with the one in this file, and
// is called once at startup.
//
// Adding a permission is therefore a code change and a restart, not a migration.
// Permissions the database knows but the code no longer enforces are NOT deleted
// -- roles may still grant them, and silently stripping authority from whoever
// held them would be worse than a warning. It logs them instead, so you can
// decide.
func (s *Service) SyncPermissions(ctx context.Context) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		for _, e := range Catalog {
			_, err := db.Exec(ctx,
				`INSERT INTO permissions (key, description)
				 VALUES ($1, $2)
				 ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description`,
				e.Key, e.Description,
			)
			if err != nil {
				return fmt.Errorf("identity: sync permission %q: %w", e.Key, err)
			}
		}

		// Anything in the table that the code no longer enforces is a dead grant:
		// roles may still carry it, and a role editor will still show it, but
		// nothing checks it.
		rows, err := db.Query(ctx, `SELECT key FROM permissions ORDER BY key`)
		if err != nil {
			return fmt.Errorf("identity: read permission catalog: %w", err)
		}
		defer rows.Close()

		var stale []string
		for rows.Next() {
			var key Permission
			if err := rows.Scan(&key); err != nil {
				return fmt.Errorf("identity: scan permission: %w", err)
			}
			if !key.Valid() {
				stale = append(stale, string(key))
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("identity: iterate permissions: %w", err)
		}

		if len(stale) > 0 {
			s.log.Warn("the database has permissions this build does not enforce -- roles may still grant them, and nothing will check them",
				slog.Any("stale_permissions", stale))
		}
		return nil
	})
}
