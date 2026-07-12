package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// joinTenant registers a user and puts them in the tenant, via the real invite +
// accept flow, holding the named system role. Using the production path rather
// than writing rows directly means the tests exercise what customers exercise.
func joinTenant(t *testing.T, svc *Service, inviter User, tenant Tenant, email, roleKey string) User {
	t.Helper()
	ctx := context.Background()

	access := accessFor(t, svc, inviter, tenant.Slug)
	roleID := systemRoleID(t, svc, tenant.ID, roleKey)

	if _, err := svc.Invite(ctx, inviter, access, email, roleID); err != nil {
		t.Fatalf("invite %s as %s: %v", email, roleKey, err)
	}
	// The token is no longer returned by the API -- it is emailed. Read it out of
	// the message, exactly as the invitee would read it out of their inbox.
	token := tokenFromLink(t, testMailer.lastTo(t, email).Body)

	user, err := svc.Register(ctx, email, goodPassword, "")
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	if _, err := svc.AcceptInvitation(ctx, user, token); err != nil {
		t.Fatalf("%s accepting the invitation: %v", email, err)
	}
	return user
}

// setupTenantWithOwner is the fixture for most of this file.
func setupTenantWithOwner(t *testing.T, svc *Service) (Tenant, User) {
	t.Helper()
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	acme, err := svc.CreateTenant(ctx, alice, "acme", "Acme Inc")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	return acme, alice
}

// ---------------------------------------------------------------- the guard

// THE test of this whole design. A role editor is a machine for handing out
// permissions; if the person operating it can hand out permissions they do not
// themselves hold, then roles.manage silently means "owner", and the entire RBAC
// model is decoration.
func TestCannotGrantPermissionsYouDoNotHold(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)

	// Mallory is an admin. Admin holds roles.manage -- she is *supposed* to be
	// able to build custom roles -- but NOT tenant.delete.
	mallory := joinTenant(t, svc, alice, acme, "mallory@example.com", RoleKeyAdmin)
	mAccess := accessFor(t, svc, mallory, acme.Slug)

	if !mAccess.Can(PermRolesCreate) {
		t.Fatal("the admin role should carry roles.manage; the fixture is wrong")
	}
	if mAccess.Can(PermTenantDelete) {
		t.Fatal("the admin role must NOT carry tenant.delete; the fixture is wrong")
	}

	t.Run("she cannot mint a role holding a permission she lacks", func(t *testing.T) {
		_, err := svc.CreateRole(ctx, mallory, mAccess, "backdoor", "Backdoor",
			[]Permission{PermTenantDelete})
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("an admin created a role carrying tenant.delete: got %v, want ErrEscalation", err)
		}
		// The refusal must say WHAT she was missing, or she files a bug report
		// about a role editor that mysteriously will not save.
		if !contains(err.Error(), string(PermTenantDelete)) {
			t.Errorf("the error does not name the missing permission: %q", err)
		}
	})

	t.Run("she cannot sneak it in among permissions she does hold", func(t *testing.T) {
		_, err := svc.CreateRole(ctx, mallory, mAccess, "mostly_fine", "Mostly Fine",
			[]Permission{PermMembersRead, PermAuditRead, PermTenantDelete})
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("got %v, want ErrEscalation", err)
		}
	})

	t.Run("she CAN build a role from permissions she holds", func(t *testing.T) {
		role, err := svc.CreateRole(ctx, mallory, mAccess, "auditor", "Auditor",
			[]Permission{PermTenantRead, PermAuditRead})
		if err != nil {
			t.Fatalf("an admin building a role within her own authority: %v", err)
		}
		if role.IsSystem {
			t.Error("a role created through the API must not be a system role")
		}
		if role.TenantID == nil || *role.TenantID != acme.ID {
			t.Error("the custom role is not scoped to the tenant that created it")
		}
	})

	t.Run("she cannot assign the owner role to herself", func(t *testing.T) {
		// No special case makes this work: the owner role carries tenant.delete,
		// which she lacks, so the ONE escalation rule catches it.
		ownerID := systemRoleID(t, svc, acme.ID, RoleKeyOwner)
		err := svc.SetMemberRoles(ctx, mallory, mAccess, mallory.ID, []uuid.UUID{ownerID})
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("an admin promoted herself to owner: got %v, want ErrEscalation", err)
		}
	})

	t.Run("she cannot invite an accomplice as an owner", func(t *testing.T) {
		// The other door into the tenant. Without the guard here, an admin who
		// cannot promote a member could simply invite a fresh account as owner and
		// log in as it.
		ownerID := systemRoleID(t, svc, acme.ID, RoleKeyOwner)
		_, err := svc.Invite(ctx, mallory, mAccess, "accomplice@example.com", ownerID)
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("an admin invited an owner: got %v, want ErrEscalation", err)
		}
	})

	t.Run("the owner may do all of it", func(t *testing.T) {
		aAccess := accessFor(t, svc, alice, acme.Slug)

		if _, err := svc.CreateRole(ctx, alice, aAccess, "destroyer", "Destroyer",
			[]Permission{PermTenantDelete}); err != nil {
			t.Errorf("an owner creating a role with tenant.delete: %v", err)
		}
		ownerID := systemRoleID(t, svc, acme.ID, RoleKeyOwner)
		if err := svc.SetMemberRoles(ctx, alice, aAccess, mallory.ID, []uuid.UUID{ownerID}); err != nil {
			t.Errorf("an owner promoting an admin to owner: %v", err)
		}
	})
}

// Editing a role is editing everyone who holds it, so the guard has to apply to
// the role's EXISTING permissions too -- not just the new ones. Otherwise an
// admin could take a role she cannot fully wield and quietly rewrite it.
func TestCannotEditARoleMorePowerfulThanYou(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	// The owner builds a powerful custom role.
	powerful, err := svc.CreateRole(ctx, alice, aAccess, "deployer", "Deployer",
		[]Permission{PermTenantRead, PermTenantDelete})
	if err != nil {
		t.Fatalf("owner creating a powerful role: %v", err)
	}

	mallory := joinTenant(t, svc, alice, acme, "mallory@example.com", RoleKeyAdmin)
	mAccess := accessFor(t, svc, mallory, acme.Slug)

	t.Run("an admin cannot rewrite it, even down to harmless permissions", func(t *testing.T) {
		// She is not GRANTING anything she lacks here -- members.read is well within
		// her authority -- but she would be stripping tenant.delete from whoever
		// holds the role, which is authority she does not have over them.
		_, err := svc.UpdateRole(ctx, mallory, mAccess, powerful.ID, "Deployer",
			[]Permission{PermMembersRead})
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("an admin rewrote a role carrying tenant.delete: got %v, want ErrEscalation", err)
		}
	})

	t.Run("nor delete it", func(t *testing.T) {
		if err := svc.DeleteRole(ctx, mallory, mAccess, powerful.ID); !errors.Is(err, ErrEscalation) {
			t.Fatalf("an admin deleted a role carrying tenant.delete: got %v, want ErrEscalation", err)
		}
	})

	t.Run("the owner can", func(t *testing.T) {
		if _, err := svc.UpdateRole(ctx, alice, aAccess, powerful.ID, "Deployer v2",
			[]Permission{PermTenantRead}); err != nil {
			t.Errorf("owner updating the role: %v", err)
		}
		if err := svc.DeleteRole(ctx, alice, aAccess, powerful.ID); err != nil {
			t.Errorf("owner deleting the role: %v", err)
		}
	})
}

// ---------------------------------------------------------------- system roles

func TestSystemRolesAreImmutable(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	// Even the owner -- who holds every permission and could not possibly be
	// escalating -- cannot touch them. If they could, a tenant could strip every
	// permission from "owner" and lock itself out permanently, with no way back
	// short of a database console.
	adminRoleID := systemRoleID(t, svc, acme.ID, RoleKeyAdmin)

	t.Run("cannot be edited", func(t *testing.T) {
		_, err := svc.UpdateRole(ctx, alice, aAccess, adminRoleID, "Hijacked", []Permission{PermTenantRead})
		if !errors.Is(err, ErrSystemRole) {
			t.Errorf("got %v, want ErrSystemRole", err)
		}
	})

	t.Run("cannot be deleted", func(t *testing.T) {
		if err := svc.DeleteRole(ctx, alice, aAccess, adminRoleID); !errors.Is(err, ErrSystemRole) {
			t.Errorf("got %v, want ErrSystemRole", err)
		}
	})

	t.Run("their keys cannot be reused by a custom role", func(t *testing.T) {
		_, err := svc.CreateRole(ctx, alice, aAccess, RoleKeyAdmin, "My Admin", []Permission{PermTenantRead})
		if !errors.Is(err, ErrRoleKeyTaken) {
			t.Errorf("got %v, want ErrRoleKeyTaken", err)
		}
	})
}

// ---------------------------------------------------------------- composition

// The reason a member may hold several roles: "a member who also does billing"
// should not require cloning the member role into a new one.
func TestPermissionsAreTheUnionOfEveryRoleHeld(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	auditor, err := svc.CreateRole(ctx, alice, aAccess, "auditor", "Auditor",
		[]Permission{PermAuditRead})
	if err != nil {
		t.Fatalf("create auditor role: %v", err)
	}

	bob := joinTenant(t, svc, alice, acme, "bob@example.com", RoleKeyMember)

	// As a plain member, Bob cannot read the audit log.
	before := accessFor(t, svc, bob, acme.Slug)
	if before.Can(PermAuditRead) {
		t.Fatal("a plain member can read the audit log; the member role is too generous")
	}
	if !before.Can(PermMembersRead) {
		t.Fatal("a plain member cannot see the tenant's members; the member role is too stingy")
	}

	// Give him BOTH member and auditor.
	memberID := systemRoleID(t, svc, acme.ID, RoleKeyMember)
	if err := svc.SetMemberRoles(ctx, alice, aAccess, bob.ID, []uuid.UUID{memberID, auditor.ID}); err != nil {
		t.Fatalf("assign member + auditor: %v", err)
	}

	after := accessFor(t, svc, bob, acme.Slug)
	if len(after.Roles) != 2 {
		t.Fatalf("bob holds %d roles, want 2: %v", len(after.Roles), roleKeys(after.Roles))
	}
	// He now has the powers of both, and neither role had to be modified.
	if !after.Can(PermAuditRead) {
		t.Error("bob cannot read the audit log despite holding the auditor role")
	}
	if !after.Can(PermMembersRead) {
		t.Error("bob lost members.read, which the member role grants")
	}
	// And nothing more.
	if after.Can(PermRolesCreate) {
		t.Error("bob gained roles.manage from nowhere")
	}
}

// ---------------------------------------------------------------- invariants

func TestLastOwnerCannotBeRemovedOrStripped(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)
	adminID := systemRoleID(t, svc, acme.ID, RoleKeyAdmin)

	t.Run("the sole owner cannot strip their own owner role", func(t *testing.T) {
		err := svc.SetMemberRoles(ctx, alice, aAccess, alice.ID, []uuid.UUID{adminID})
		if !errors.Is(err, ErrLastOwner) {
			t.Errorf("got %v, want ErrLastOwner", err)
		}
	})

	t.Run("the sole owner cannot leave", func(t *testing.T) {
		if err := svc.RemoveMember(ctx, alice, aAccess, alice.ID); !errors.Is(err, ErrLastOwner) {
			t.Errorf("got %v, want ErrLastOwner", err)
		}
	})

	t.Run("a member holding no roles at all is refused", func(t *testing.T) {
		// Not a role change but a deletion of the person's entire access. They
		// meant to remove them from the tenant.
		if err := svc.SetMemberRoles(ctx, alice, aAccess, alice.ID, nil); !errors.Is(err, ErrNoRoles) {
			t.Errorf("got %v, want ErrNoRoles", err)
		}
	})

	// With a second owner in place, both become legal.
	bob := joinTenant(t, svc, alice, acme, "bob@example.com", RoleKeyOwner)

	t.Run("with a second owner, the first may leave", func(t *testing.T) {
		if err := svc.RemoveMember(ctx, alice, aAccess, alice.ID); err != nil {
			t.Fatalf("alice leaving while bob is also an owner: %v", err)
		}
		// And now Bob is the last owner, so he is stuck the same way.
		bAccess := accessFor(t, svc, bob, acme.Slug)
		if err := svc.RemoveMember(ctx, bob, bAccess, bob.ID); !errors.Is(err, ErrLastOwner) {
			t.Errorf("bob is now the last owner: got %v, want ErrLastOwner", err)
		}
	})
}

// An admin holds members.remove, so the permission check passes -- but permissions
// alone would let them evict somebody strictly more powerful than themselves.
func TestAdminsCannotTouchOwners(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	mallory := joinTenant(t, svc, alice, acme, "mallory@example.com", RoleKeyAdmin)
	mAccess := accessFor(t, svc, mallory, acme.Slug)

	if !mAccess.Can(PermMembersDelete) {
		t.Fatal("the admin role should carry members.remove; the fixture is wrong")
	}

	t.Run("an admin cannot remove an owner", func(t *testing.T) {
		if err := svc.RemoveMember(ctx, mallory, mAccess, alice.ID); !errors.Is(err, ErrForbidden) {
			t.Errorf("got %v, want ErrForbidden", err)
		}
	})

	t.Run("an admin cannot demote an owner", func(t *testing.T) {
		memberID := systemRoleID(t, svc, acme.ID, RoleKeyMember)
		err := svc.SetMemberRoles(ctx, mallory, mAccess, alice.ID, []uuid.UUID{memberID})
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("got %v, want ErrForbidden", err)
		}
	})
}

// ---------------------------------------------------------------- deletion

func TestCannotDeleteARoleSomebodyHolds(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	auditor, err := svc.CreateRole(ctx, alice, aAccess, "auditor", "Auditor", []Permission{PermAuditRead})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	bob := joinTenant(t, svc, alice, acme, "bob@example.com", RoleKeyMember)
	memberID := systemRoleID(t, svc, acme.ID, RoleKeyMember)

	if err := svc.SetMemberRoles(ctx, alice, aAccess, bob.ID, []uuid.UUID{memberID, auditor.ID}); err != nil {
		t.Fatalf("assign auditor to bob: %v", err)
	}

	// Deleting it now would silently strip Bob's access as a side effect of
	// tidying up. Refuse, loudly.
	if err := svc.DeleteRole(ctx, alice, aAccess, auditor.ID); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("deleting a role somebody holds: got %v, want ErrRoleInUse", err)
	}

	// Reassign Bob, and the delete goes through.
	if err := svc.SetMemberRoles(ctx, alice, aAccess, bob.ID, []uuid.UUID{memberID}); err != nil {
		t.Fatalf("reassign bob: %v", err)
	}
	if err := svc.DeleteRole(ctx, alice, aAccess, auditor.ID); err != nil {
		t.Errorf("deleting an unheld role: %v", err)
	}
}

// ---------------------------------------------------------------- validation

func TestRoleValidation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	t.Run("a permission no code enforces is rejected", func(t *testing.T) {
		// The FK on role_permissions would catch this too, but that would be a 500.
		// Catching it in the service is a 400 that says which permission is bogus.
		_, err := svc.CreateRole(ctx, alice, aAccess, "bogus", "Bogus",
			[]Permission{"billing.refund"}) // plausible, and enforced by nothing
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("got %v, want ErrValidation", err)
		}
		if !contains(err.Error(), "billing.refund") {
			t.Errorf("the error does not name the bogus permission: %q", err)
		}
	})

	t.Run("bad keys are rejected", func(t *testing.T) {
		for _, key := range []string{
			"",                 // empty
			"billing manager",  // space
			"billing-manager",  // hyphen (keys use underscores)
			"_billing",         // leading underscore
			"billing_",         // trailing underscore
			"billing__manager", // double underscore
		} {
			if _, err := svc.CreateRole(ctx, alice, aAccess, key, "X", []Permission{PermTenantRead}); !errors.Is(err, ErrValidation) {
				t.Errorf("key %q: got %v, want ErrValidation", key, err)
			}
		}
	})

	// Case and surrounding space are normalised away rather than rejected, exactly
	// as tenant slugs are: "Billing" plainly means the "billing" role.
	t.Run("keys are normalised, not rejected, for case and space", func(t *testing.T) {
		role, err := svc.CreateRole(ctx, alice, aAccess, "  BillingManager  ", "Billing Manager",
			[]Permission{PermTenantRead})
		if err != nil {
			t.Fatalf("create role with a messy key: %v", err)
		}
		if role.Key != "billingmanager" {
			t.Errorf("key is %q, want it lowercased and trimmed", role.Key)
		}
	})

	t.Run("a role granting nothing is rejected", func(t *testing.T) {
		if _, err := svc.CreateRole(ctx, alice, aAccess, "empty", "Empty", nil); !errors.Is(err, ErrValidation) {
			t.Errorf("got %v, want ErrValidation", err)
		}
	})
}

// ---------------------------------------------------------------- pure units

func TestPermissionSet(t *testing.T) {
	s := NewPermissionSet(PermTenantRead, PermAuditRead)

	if !s.Has(PermTenantRead) {
		t.Error("Has says the set lacks a permission it was built with")
	}
	if s.Has(PermTenantDelete) {
		t.Error("Has says the set holds a permission it never got")
	}

	// Superset IS the escalation guard, so its edges matter.
	if !s.Superset(NewPermissionSet(PermTenantRead)) {
		t.Error("a set must be a superset of its own subset")
	}
	if !s.Superset(NewPermissionSet()) {
		t.Error("every set is a superset of the empty set")
	}
	if s.Superset(NewPermissionSet(PermTenantRead, PermTenantDelete)) {
		t.Error("Superset accepted a permission the actor does not hold: this is the escalation hole")
	}
	if !AllPermissions().Superset(s) {
		t.Error("the full catalog must be a superset of everything")
	}

	missing := s.Missing(NewPermissionSet(PermTenantRead, PermTenantDelete, PermRolesCreate))
	if len(missing) != 2 {
		t.Fatalf("Missing returned %v, want the 2 permissions the set lacks", missing)
	}
	// Sorted, so error messages and tests are stable.
	if missing[0] != PermRolesCreate || missing[1] != PermTenantDelete {
		t.Errorf("Missing returned %v, want it sorted", missing)
	}
}

func TestCatalogIsConsistent(t *testing.T) {
	seen := map[Permission]bool{}
	for _, e := range Catalog {
		if seen[e.Key] {
			t.Errorf("permission %q appears twice in the catalog", e.Key)
		}
		seen[e.Key] = true

		if e.Description == "" {
			t.Errorf("permission %q has no description; a role editor would render a blank checkbox", e.Key)
		}
		if !e.Key.Valid() {
			t.Errorf("permission %q is in the catalog but Valid() rejects it", e.Key)
		}
	}

	if Permission("billing.refund").Valid() {
		t.Error("Valid() accepted a permission that is not in the catalog")
	}
}

// contains is strings.Contains, named for what the assertions are asking.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
