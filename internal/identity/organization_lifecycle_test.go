package identity

import (
	"context"
	"errors"
	"testing"
)

// Renaming, deleting, and restoring an organization. The soft delete is the interesting
// one: it must be total (nobody, not even the owner, can see the organization) while
// destroying nothing.

func TestUpdateOrganizationChangesTheNameOnly(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	updated, err := svc.UpdateOrganization(ctx, alice, aAccess, "Acme Corporation")
	if err != nil {
		t.Fatalf("rename organization: %v", err)
	}
	if updated.Name != "Acme Corporation" {
		t.Errorf("name is %q, want it renamed", updated.Name)
	}
	// The slug is an identifier, in every URL and bookmark the customer has. The
	// service has no parameter that could change it, and this is the assertion that
	// keeps it that way.
	if updated.Slug != acme.Slug {
		t.Errorf("the slug changed from %q to %q; it is supposed to be immutable", acme.Slug, updated.Slug)
	}

	t.Run("an empty name is rejected", func(t *testing.T) {
		if _, err := svc.UpdateOrganization(ctx, alice, aAccess, "   "); !errors.Is(err, ErrValidation) {
			t.Errorf("got %v, want ErrValidation", err)
		}
	})
}

func TestSoftDeleteIsTotalButDestroysNothing(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	bob := joinOrganization(t, svc, alice, acme, "bob@example.com", RoleKeyMember)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	if err := svc.DeleteOrganization(ctx, alice, aAccess); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	// Total: the OWNER who just deleted it cannot see it either. A soft delete that
	// leaves the organization reachable by its owner is not a delete, it is a flag.
	t.Run("invisible to its owner", func(t *testing.T) {
		if _, err := svc.ResolveOrganization(ctx, alice, "acme"); !errors.Is(err, ErrNotFound) {
			t.Errorf("the owner can still resolve the deleted organization: got %v, want ErrNotFound", err)
		}
	})

	t.Run("invisible to its members", func(t *testing.T) {
		if _, err := svc.ResolveOrganization(ctx, bob, "acme"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a member can still resolve the deleted organization: got %v, want ErrNotFound", err)
		}
	})

	t.Run("gone from everyone's organization list", func(t *testing.T) {
		for _, u := range []User{alice, bob} {
			organizations, err := svc.ListOrganizations(ctx, u.ID)
			if err != nil {
				t.Fatalf("list organizations for %s: %v", u.Email, err)
			}
			if len(organizations) != 0 {
				t.Errorf("%s still lists %d organizations after the deletion", u.Email, len(organizations))
			}
		}
	})

	// ...but nothing is destroyed. Every membership row is still there, which is
	// what makes the restore whole rather than a resurrection of an empty shell.
	t.Run("the memberships survive", func(t *testing.T) {
		members, err := svc.ListMembers(ctx, acme.ID)
		if err != nil {
			t.Fatalf("list members of a deleted organization: %v", err)
		}
		if len(members) != 2 {
			t.Errorf("the deleted organization has %d members, want 2 -- the data should be intact", len(members))
		}
	})

	t.Run("deleting it twice is ErrNotFound", func(t *testing.T) {
		// aAccess is stale by design: it was captured while the organization lived. The
		// repository refuses anyway, because its WHERE clause filters deleted rows.
		if err := svc.DeleteOrganization(ctx, alice, aAccess); !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}

// Deleting an organization releases its slug. That is a real feature -- and it is exactly
// what makes restore fallible.
func TestDeleteFreesTheSlugAndRestoreCopes(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	root := makeSuperuser(t, svc, "root@example.com")

	if err := svc.DeleteOrganization(ctx, alice, accessFor(t, svc, alice, acme.Slug)); err != nil {
		t.Fatalf("delete acme: %v", err)
	}

	t.Run("the slug can be claimed by somebody else", func(t *testing.T) {
		bob, err := svc.Register(ctx, "bob@example.com", goodPassword, "Bob")
		if err != nil {
			t.Fatalf("register bob: %v", err)
		}
		// The partial unique index covers live organizations only, so "acme" is free.
		if _, err := svc.CreateOrganization(ctx, bob, "acme", "Bob's Acme"); err != nil {
			t.Fatalf("bob claiming the freed slug: %v", err)
		}
	})

	t.Run("restoring under the taken slug is refused", func(t *testing.T) {
		// There is no room for two live organizations on one slug, and Bob got there first.
		if _, err := svc.RestoreOrganization(ctx, root, acme.ID, ""); !errors.Is(err, ErrSlugTaken) {
			t.Fatalf("got %v, want ErrSlugTaken", err)
		}
	})

	t.Run("restoring under a new slug works", func(t *testing.T) {
		restored, err := svc.RestoreOrganization(ctx, root, acme.ID, "acme-original")
		if err != nil {
			t.Fatalf("restore under a new slug: %v", err)
		}
		if restored.Slug != "acme-original" {
			t.Errorf("restored slug is %q, want acme-original", restored.Slug)
		}
		if restored.IsDeleted() {
			t.Error("the restored organization is still flagged deleted")
		}

		// And it comes back WHOLE: the owner can reach it again, with her role and
		// permissions intact, because none of that was ever destroyed.
		access, err := svc.ResolveOrganization(ctx, alice, "acme-original")
		if err != nil {
			t.Fatalf("the owner cannot reach her restored organization: %v", err)
		}
		if !hasOwnerRole(access.Roles) {
			t.Errorf("the owner came back holding %v, want the owner role", roleKeys(access.Roles))
		}
	})
}

// The straightforward case: nobody took the slug, so the organization comes back on the
// URL it had.
func TestRestoreKeepsTheOriginalSlugWhenItIsStillFree(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	root := makeSuperuser(t, svc, "root@example.com")

	if err := svc.DeleteOrganization(ctx, alice, accessFor(t, svc, alice, acme.Slug)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	restored, err := svc.RestoreOrganization(ctx, root, acme.ID, "")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.Slug != "acme" {
		t.Errorf("restored slug is %q, want the original 'acme'", restored.Slug)
	}

	t.Run("restoring an organization that is not deleted is ErrNotFound", func(t *testing.T) {
		if _, err := svc.RestoreOrganization(ctx, root, acme.ID, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})
}

// A deleted organization 404s for its own owners, so somebody outside it has to be able
// to find one in order to restore it. An invisible deleted organization is an
// unrestorable one.
func TestDeletedOrganizationsRemainVisibleToTheSuperuser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	if err := svc.DeleteOrganization(ctx, alice, accessFor(t, svc, alice, acme.Slug)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	organizations, err := svc.ListAllOrganizations(ctx, [16]byte{}, 50)
	if err != nil {
		t.Fatalf("list all organizations: %v", err)
	}

	var found bool
	for _, ts := range organizations {
		if ts.Organization.ID != acme.ID {
			continue
		}
		found = true
		if !ts.Organization.IsDeleted() {
			t.Error("the staff surface shows the organization but does not flag it as deleted")
		}
	}
	if !found {
		t.Fatal("a deleted organization is invisible to the superuser: nobody could ever restore it")
	}
}
