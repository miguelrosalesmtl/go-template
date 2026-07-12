package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// This file is the reason the template chose application-level tenant scoping
// over Postgres row-level security: with RLS, the database refuses cross-tenant
// rows and these tests would be redundant. Without it, one forgotten WHERE
// clause is a data breach, and THESE TESTS ARE THE THING THAT CATCHES IT.
//
// When you add a tenant-owned resource of your own, add its isolation test here
// too. It is the cheapest insurance in the codebase.

// setupTwoTenants builds the standard fixture: two unrelated tenants, each with
// an owner who has no membership in the other.
func setupTwoTenants(t *testing.T, svc *Service) (acme, globex Tenant, alice, bob User) {
	t.Helper()
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", "correct-horse-battery", "Alice")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	bob, err = svc.Register(ctx, "bob@example.com", "correct-horse-battery", "Bob")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}

	acme, err = svc.CreateTenant(ctx, alice, "acme", "Acme Inc")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err = svc.CreateTenant(ctx, bob, "globex", "Globex Corp")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	return acme, globex, alice, bob
}

// The headline test: a member of one tenant must not be able to reach another,
// even knowing its slug and its ID.
func TestTenantIsolation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, globex, alice, bob := setupTwoTenants(t, svc)

	t.Run("cannot resolve a tenant they do not belong to", func(t *testing.T) {
		// Alice knows Globex exists -- she can read the slug off a URL. Resolving
		// it must still fail, and must fail as "not found" rather than
		// "forbidden": a 403 would confirm the tenant exists, letting anyone
		// enumerate the customer list one slug at a time.
		if _, err := svc.ResolveTenant(ctx, alice, "globex"); !errors.Is(err, ErrNotFound) {
			t.Errorf("alice resolving globex: got %v, want ErrNotFound", err)
		}
		if _, err := svc.ResolveTenant(ctx, bob, "acme"); !errors.Is(err, ErrNotFound) {
			t.Errorf("bob resolving acme: got %v, want ErrNotFound", err)
		}
	})

	t.Run("a tenant that does not exist is indistinguishable", func(t *testing.T) {
		_, err := svc.ResolveTenant(ctx, alice, "no-such-tenant")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("resolving a nonexistent tenant: got %v, want ErrNotFound", err)
		}
	})

	t.Run("listing tenants shows only your own", func(t *testing.T) {
		tenants, err := svc.ListTenants(ctx, alice.ID)
		if err != nil {
			t.Fatalf("list tenants: %v", err)
		}
		if len(tenants) != 1 {
			t.Fatalf("alice belongs to %d tenants, want 1", len(tenants))
		}
		if tenants[0].Tenant.ID != acme.ID {
			t.Errorf("alice's tenant is %s, want acme", tenants[0].Tenant.Slug)
		}
		if !hasOwnerRole(tenants[0].Roles) {
			t.Errorf("the creator holds %v, want the owner role", roleKeys(tenants[0].Roles))
		}
	})

	t.Run("members of one tenant are invisible to another", func(t *testing.T) {
		members, err := svc.ListMembers(ctx, globex.ID)
		if err != nil {
			t.Fatalf("list members: %v", err)
		}
		for _, m := range members {
			if m.UserID == alice.ID {
				t.Fatal("alice appears in globex's member list")
			}
		}
		if len(members) != 1 || members[0].UserID != bob.ID {
			t.Fatalf("globex has %d members, want exactly bob", len(members))
		}
	})

	// The repository-level version of the same rule. ResolveTenant is the gate an
	// HTTP request passes through, but a future handler could call the repository
	// directly -- so the WHERE clause itself has to be right, not just the gate
	// in front of it.
	t.Run("repository writes are scoped by tenant_id", func(t *testing.T) {
		repo := NewRepository(testPool)

		// Bob is an owner of Globex. An attacker who compromised an Acme admin
		// should not be able to touch his Globex membership by passing Acme's
		// tenant ID with Bob's user ID -- the tenant_id in the WHERE clause is
		// what makes the row unreachable.
		err := repo.DeleteMembership(ctx, acme.ID, bob.ID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting bob's membership via acme's tenant id: got %v, want ErrNotFound", err)
		}

		// And Bob is still an owner of Globex, untouched.
		roles, err := repo.LoadMemberRoles(ctx, bob.ID, globex.ID)
		if err != nil {
			t.Fatalf("bob's globex membership should be intact: %v", err)
		}
		if !hasOwnerRole(roles) {
			t.Errorf("bob now holds %v in globex, want the owner role", roleKeys(roles))
		}
	})

	// RBAC adds a new object that can leak across tenants: the ROLE. A custom role
	// belongs to exactly one tenant, and its id is a guessable-shaped UUID that
	// might appear in a screenshot or a log. Assigning, editing, or inviting into
	// another tenant's role must be impossible.
	t.Run("a tenant cannot use another tenant's custom role", func(t *testing.T) {
		bAccess := accessFor(t, svc, bob, globex.Slug)

		// Globex builds a custom role. Acme must not be able to touch it.
		secret, err := svc.CreateRole(ctx, bob, bAccess, "globex_only", "Globex Only",
			[]Permission{PermAuditRead})
		if err != nil {
			t.Fatalf("bob creating a role in globex: %v", err)
		}

		aAccess := accessFor(t, svc, alice, acme.Slug)

		// Alice is an OWNER of Acme -- she holds every permission, so the escalation
		// guard cannot be what stops her. Only the tenant scoping can.
		if _, err := svc.GetRole(ctx, acme.ID, secret.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("acme can read globex's role: got %v, want ErrNotFound", err)
		}

		carol := joinTenant(t, svc, alice, acme, "carol@example.com", RoleKeyMember)
		err = svc.SetMemberRoles(ctx, alice, aAccess, carol.ID, []uuid.UUID{secret.ID})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("acme assigned globex's role to its own member: got %v, want ErrNotFound", err)
		}

		_, err = svc.Invite(ctx, alice, aAccess, "dave@example.com", secret.ID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("acme invited somebody into globex's role: got %v, want ErrNotFound", err)
		}

		if _, err := svc.UpdateRole(ctx, alice, aAccess, secret.ID, "Hijacked",
			[]Permission{PermTenantRead}); !errors.Is(err, ErrNotFound) {
			t.Errorf("acme edited globex's role: got %v, want ErrNotFound", err)
		}
		if err := svc.DeleteRole(ctx, alice, aAccess, secret.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("acme deleted globex's role: got %v, want ErrNotFound", err)
		}

		// Globex's role list is unaffected; Acme's never contained it.
		acmeRoles, err := svc.ListRoles(ctx, acme.ID)
		if err != nil {
			t.Fatalf("list acme roles: %v", err)
		}
		for _, r := range acmeRoles {
			if r.ID == secret.ID {
				t.Fatal("globex's custom role appears in acme's role list")
			}
		}
	})

	t.Run("an admin cannot revoke another tenant's invitation", func(t *testing.T) {
		// Bob invites someone to Globex.
		bAccess := accessFor(t, svc, bob, globex.Slug)
		memberID := systemRoleID(t, svc, globex.ID, RoleKeyMember)

		inv, err := svc.Invite(ctx, bob, bAccess, "carol@example.com", memberID)
		if err != nil {
			t.Fatalf("invite to globex: %v", err)
		}

		// Alice, an owner of Acme, tries to revoke it using its ID.
		err = svc.RevokeInvitation(ctx, alice, acme, inv.ID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("alice revoking globex's invitation: got %v, want ErrNotFound", err)
		}

		// It is still live.
		pending, err := svc.ListInvitations(ctx, globex.ID)
		if err != nil {
			t.Fatalf("list globex invitations: %v", err)
		}
		if len(pending) != 1 {
			t.Fatalf("globex has %d pending invitations, want 1 -- alice revoked it", len(pending))
		}
	})

	t.Run("the audit log does not leak across tenants", func(t *testing.T) {
		entries := listAudit(t, acme.ID)
		for _, e := range entries {
			if e.TenantID == nil {
				t.Fatal("a tenant-scoped audit entry has a nil tenant_id")
			}
			if *e.TenantID != acme.ID {
				t.Fatalf("acme's audit log contains an entry for tenant %s", *e.TenantID)
			}
		}
		if len(entries) == 0 {
			t.Fatal("acme's audit log is empty; creating the tenant should have been recorded")
		}
	})
}

// An invitation is a bearer token, and bearer tokens leak: they get forwarded,
// screenshotted, and left in inboxes. Binding the invitation to the invited
// email is what stops a leaked link from becoming an account in someone else's
// tenant.
func TestInvitationCannotBeRedeemedByAnotherUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, _, alice, bob := setupTwoTenants(t, svc)

	// Alice invites Carol to Acme.
	aAccess := accessFor(t, svc, alice, acme.Slug)
	adminID := systemRoleID(t, svc, acme.ID, RoleKeyAdmin)

	if _, err := svc.Invite(ctx, alice, aAccess, "carol@example.com", adminID); err != nil {
		t.Fatalf("invite carol: %v", err)
	}

	// The token is emailed, never returned. Read it out of Carol's message -- which
	// is the ONLY way to get one now, and is exactly the point: an admin can no
	// longer keep a working link for an address they do not control.
	token := tokenFromLink(t, testMailer.lastTo(t, "carol@example.com").Body)

	// Bob gets hold of the link anyway (forwarded, screenshotted, leaked from an
	// inbox) and tries to redeem it.
	if _, err := svc.AcceptInvitation(ctx, bob, token); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("bob redeeming carol's invitation: got %v, want ErrInvitationInvalid", err)
	}

	// Bob did not join.
	members, err := svc.ListMembers(ctx, acme.ID)
	if err != nil {
		t.Fatalf("list acme members: %v", err)
	}
	for _, m := range members {
		if m.UserID == bob.ID {
			t.Fatal("bob joined acme with an invitation addressed to carol")
		}
	}

	// Carol, once registered, can still use it -- the token was not consumed.
	carol, err := svc.Register(ctx, "carol@example.com", "correct-horse-battery", "Carol")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	tenant, err := svc.AcceptInvitation(ctx, carol, token)
	if err != nil {
		t.Fatalf("carol accepting her own invitation: %v", err)
	}
	if tenant.ID != acme.ID {
		t.Errorf("carol joined tenant %s, want acme", tenant.Slug)
	}

	// And it cannot be replayed.
	if _, err := svc.AcceptInvitation(ctx, carol, token); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("reusing a spent invitation: got %v, want ErrInvitationInvalid", err)
	}
}

// listAudit reads a tenant's audit entries, bypassing the service (which has no
// audit-read method of its own -- the handler uses audit.Recorder directly).
func listAudit(t *testing.T, tenantID uuid.UUID) []auditRow {
	t.Helper()

	rows, err := testPool.Query(context.Background(),
		`SELECT id, tenant_id, action FROM audit_log WHERE tenant_id = $1`, tenantID)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Action); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit log: %v", err)
	}
	return out
}

type auditRow struct {
	ID       uuid.UUID
	TenantID *uuid.UUID
	Action   string
}
