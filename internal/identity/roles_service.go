package identity

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// The RBAC rules. Everything in this file exists to stop one thing:
//
//	SOMEONE GRANTING THEMSELVES AUTHORITY THEY DO NOT HAVE.
//
// A role editor is, by construction, a machine for handing out permissions. Give
// an admin roles.manage without a guard and they will simply build a role holding
// tenant.delete, assign it to themselves, and walk out through every limit you
// placed on them. The guard is checkEscalation, and it is called on every path
// that can move a permission from one person to another.

// roleKeyPattern is what a custom role's key may look like. It ends up in APIs
// and configuration, so it is deliberately boring.
var roleKeyPattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

// ListRoles returns the roles the tenant can use: the three system roles plus its
// own custom ones.
func (s *Service) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	return s.repo.ListRoles(ctx, tenantID)
}

// GetRole returns one role the tenant can see.
func (s *Service) GetRole(ctx context.Context, tenantID, roleID uuid.UUID) (Role, error) {
	return s.repo.GetRole(ctx, tenantID, roleID)
}

// CreateRole builds a new custom role for the tenant.
//
// The caller needs roles.manage AND must already hold every permission they are
// putting into the new role. The second condition is the whole ballgame -- without
// it, roles.manage would be a synonym for "may become an owner".
func (s *Service) CreateRole(
	ctx context.Context, actor User, access TenantAccess, key, name string, perms []Permission,
) (Role, error) {
	key, name, set, err := s.validateRoleInput(key, name, perms)
	if err != nil {
		return Role{}, err
	}
	if err := checkEscalation(access, set); err != nil {
		return Role{}, err
	}

	var role Role
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// A custom role may not shadow a system role's key: every tenant already
		// has "owner", "admin", and "member", and two roles answering to the same
		// key would make "which role is this?" ambiguous.
		if _, err := repo.GetRoleByKey(ctx, access.Tenant.ID, key); err == nil {
			return ErrRoleKeyTaken
		} else if !isNotFound(err) {
			return err
		}

		role, err = repo.CreateRole(ctx, access.Tenant.ID, key, name, set)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			TenantID:    &access.Tenant.ID,
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleCreated,
			TargetType:  "role",
			TargetID:    role.ID.String(),
			Metadata: map[string]any{
				"key":         key,
				"name":        name,
				"permissions": set.Slice(),
			},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// UpdateRole renames a custom role and replaces its permissions wholesale.
//
// Two refusals matter here. A system role cannot be touched at all -- otherwise a
// tenant could strip every permission from "owner" and lock itself out forever.
// And the caller cannot put a permission into the role that they do not hold
// themselves, which is the same escalation guard as CreateRole: editing an
// existing role would otherwise be the trivial way around it.
func (s *Service) UpdateRole(
	ctx context.Context, actor User, access TenantAccess, roleID uuid.UUID, name string, perms []Permission,
) (Role, error) {
	_, name, set, err := s.validateRoleInput("placeholder", name, perms)
	if err != nil {
		return Role{}, err
	}
	if err := checkEscalation(access, set); err != nil {
		return Role{}, err
	}

	var role Role
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		existing, err := repo.GetRole(ctx, access.Tenant.ID, roleID)
		if err != nil {
			return err
		}
		if existing.IsSystem {
			return ErrSystemRole
		}

		// The caller must also hold everything the role ALREADY grants. Otherwise
		// an admin could take a powerful role they cannot fully wield and quietly
		// rewrite it -- stripping permissions from whoever holds it, or keeping the
		// ones they want. Editing a role is editing everyone who holds it.
		if err := checkEscalation(access, existing.Permissions); err != nil {
			return err
		}

		role, err = repo.UpdateRole(ctx, access.Tenant.ID, roleID, name, set)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			TenantID:    &access.Tenant.ID,
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleUpdated,
			TargetType:  "role",
			TargetID:    role.ID.String(),
			Metadata: map[string]any{
				"key":  role.Key,
				"from": existing.Permissions.Slice(),
				"to":   set.Slice(),
			},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// DeleteRole removes a custom role.
//
// It fails with ErrRoleInUse while anyone still holds the role. Reassign them
// first: deleting a role should not silently strip somebody's access as an
// invisible side effect of tidying up.
func (s *Service) DeleteRole(ctx context.Context, actor User, access TenantAccess, roleID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		existing, err := repo.GetRole(ctx, access.Tenant.ID, roleID)
		if err != nil {
			return err
		}
		if existing.IsSystem {
			return ErrSystemRole
		}
		// Same reasoning as UpdateRole: you may not destroy authority you do not
		// yourself hold.
		if err := checkEscalation(access, existing.Permissions); err != nil {
			return err
		}

		if err := repo.DeleteRole(ctx, access.Tenant.ID, roleID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			TenantID:    &access.Tenant.ID,
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleDeleted,
			TargetType:  "role",
			TargetID:    roleID.String(),
			Metadata:    map[string]any{"key": existing.Key},
		})
	})
}

// SetMemberRoles replaces the set of roles a member holds.
//
// This is the other door authority can walk through, so it takes the same guard:
// the caller must hold every permission carried by every role they are assigning.
// That one rule also makes "only an owner may create an owner" fall out for free
// -- the owner role carries tenant.delete, which an admin does not have, so an
// admin assigning it fails without any special case for owners anywhere.
func (s *Service) SetMemberRoles(
	ctx context.Context, actor User, access TenantAccess, targetUserID uuid.UUID, roleIDs []uuid.UUID,
) error {
	if len(roleIDs) == 0 {
		// A member holding no roles can see nothing and do nothing. That is not a
		// state anyone means to create; they meant to remove them from the tenant.
		return ErrNoRoles
	}

	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Serialise membership changes for this tenant, so the owner count read
		// below cannot go stale between the check and the write.
		if err := repo.LockTenant(ctx, access.Tenant.ID); err != nil {
			return err
		}

		membership, err := repo.GetMembership(ctx, targetUserID, access.Tenant.ID)
		if err != nil {
			return err
		}

		// Resolving the ids through the tenant is what stops an admin of tenant A
		// from assigning tenant B's role by id: GetRolesByIDs only sees system
		// roles and this tenant's own, and returns ErrNotFound if any id is
		// outside that set.
		roles, err := repo.GetRolesByIDs(ctx, access.Tenant.ID, roleIDs)
		if err != nil {
			return err
		}

		// THE GUARD: you cannot hand out what you do not hold.
		if err := checkEscalation(access, unionPermissions(roles)); err != nil {
			return err
		}

		before, err := repo.LoadMemberRoles(ctx, targetUserID, access.Tenant.ID)
		if err != nil {
			return err
		}

		// Demoting an owner is itself an owner-level act. Without this, an admin
		// could strip the owner down to "member" -- they are not GRANTING anything
		// they lack, so checkEscalation would happily let it pass, but they would
		// have neutered somebody strictly more powerful than themselves.
		//
		// This is checked BEFORE the last-owner invariant below, and the order is
		// deliberate: authorization first, invariants second. Otherwise an admin
		// attempting the demotion would be told "that is the last owner" -- a fact
		// about the tenant's composition that someone with no business acting here
		// has no business learning.
		if hasOwnerRole(before) && !access.ViaSuperuser && !actorHoldsOwner(access) {
			return ErrForbidden
		}

		// Taking the owner role away from somebody who has it: refuse if they are
		// the last owner, or the tenant becomes unadministrable by anyone.
		if hasOwnerRole(before) && !hasOwnerRole(roles) {
			owners, err := repo.CountOwners(ctx, access.Tenant.ID)
			if err != nil {
				return err
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}

		if err := repo.SetMembershipRoles(ctx, membership.ID, rolesToIDs(roles)); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			TenantID:    &access.Tenant.ID,
			ActorUserID: &actor.ID,
			Action:      audit.ActionMemberUpdated,
			TargetType:  "user",
			TargetID:    targetUserID.String(),
			Metadata: map[string]any{
				"from": roleKeys(before),
				"to":   roleKeys(roles),
			},
		})
	})
}

// ---------------------------------------------------------------- the guard

// checkEscalation is the single rule that keeps RBAC from defeating itself:
//
//	YOU MAY ONLY GRANT PERMISSIONS YOU YOURSELF HOLD.
//
// It is called before creating a role, before editing one, and before assigning
// one to a member -- every path by which a permission can travel from the system
// to a person.
//
// The error names the permissions the caller was missing, because "forbidden"
// with no explanation is how an admin ends up filing a bug report about a role
// editor that mysteriously refuses to save.
func checkEscalation(actor TenantAccess, granting PermissionSet) error {
	if actor.Permissions.Superset(granting) {
		return nil
	}

	missing := actor.Permissions.Missing(granting)
	names := make([]string, 0, len(missing))
	for _, p := range missing {
		names = append(names, string(p))
	}
	return fmt.Errorf("%w: you do not hold %s", ErrEscalation, strings.Join(names, ", "))
}

// actorHoldsOwner reports whether the caller genuinely holds the system owner
// role in this tenant (as opposed to merely holding every permission, which a
// custom role could in principle also do).
func actorHoldsOwner(access TenantAccess) bool {
	return hasOwnerRole(access.Roles)
}

// ---------------------------------------------------------------- validation

// validateRoleInput normalises and checks a role's key, name, and permissions.
//
// Every permission must be in the Catalog. The database's foreign key would catch
// an unknown one anyway, but that would be a 500; catching it here is a 400 that
// says which permission does not exist.
func (s *Service) validateRoleInput(key, name string, perms []Permission) (string, string, PermissionSet, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	name = strings.TrimSpace(name)

	switch {
	case key == "":
		return "", "", nil, invalid("role key is required")
	case len(key) > 63:
		return "", "", nil, invalid("role key must be at most 63 characters")
	case !roleKeyPattern.MatchString(key):
		return "", "", nil, invalid("role key may contain only lowercase letters, digits, and single underscores between them")
	case name == "":
		return "", "", nil, invalid("role name is required")
	case len(name) > 100:
		return "", "", nil, invalid("role name must be at most 100 characters")
	case len(perms) == 0:
		return "", "", nil, invalid("a role must grant at least one permission")
	}

	set := PermissionSet{}
	for _, p := range perms {
		if !p.Valid() {
			return "", "", nil, invalid(fmt.Sprintf("%q is not a permission this application enforces", p))
		}
		set[p] = struct{}{}
	}
	return key, name, set, nil
}

// roleKeys is a small helper for audit metadata.
func roleKeys(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Key)
	}
	return out
}
