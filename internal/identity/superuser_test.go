package identity

import (
	"context"
	"errors"
	"testing"
)

// The superuser is the one global privilege in the system, and the only way a
// person can act outside an organization they belong to. These tests pin down exactly
// what it grants -- and, just as importantly, what it does not.

// makeSuperuser registers a user and grants the flag the only way it can be
// granted: through the service method the CLI calls. There is no HTTP route.
func makeSuperuser(t *testing.T, svc *Service, email string) User {
	t.Helper()
	ctx := context.Background()

	if _, err := svc.Register(ctx, email, goodPassword, "Root"); err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	root, err := svc.SetSuperuser(ctx, email, true)
	if err != nil {
		t.Fatalf("grant superuser to %s: %v", email, err)
	}
	if !root.IsSuperuser {
		t.Fatalf("%s is not flagged as a superuser after the grant", email)
	}
	return root
}

func TestSuperuserBypassesOrganizationMembership(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, _, alice, _ := setupTwoOrganizations(t, svc)
	root := makeSuperuser(t, svc, "root@example.com")

	t.Run("enters an organization it has no membership in", func(t *testing.T) {
		access, err := svc.ResolveOrganization(ctx, root, "acme")
		if err != nil {
			t.Fatalf("superuser resolving acme: %v", err)
		}
		// A superuser holds every permission in the catalog, which is what makes
		// every requirePermission check pass without the middleware having to
		// special-case them anywhere.
		if !access.Permissions.Superset(AllPermissions()) {
			t.Errorf("the superuser lacks %v", AllPermissions().Missing(access.Permissions))
		}
		// But they hold no ROLE: they are not a member of anything. They do not
		// outrank the roles, they outrank the question.
		if len(access.Roles) != 0 {
			t.Errorf("the superuser holds roles %v; they should hold none", roleKeys(access.Roles))
		}
		// And the access must be marked, or it would be indistinguishable from a
		// real owner's and could not be audited.
		if !access.ViaSuperuser {
			t.Error("the bypass was not flagged: this access would go unaudited")
		}
	})

	t.Run("an ordinary user still cannot", func(t *testing.T) {
		// The control. If this ever passes, the bypass has leaked to everyone.
		if _, err := svc.ResolveOrganization(ctx, alice, "globex"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a non-superuser reached another organization: got %v, want ErrNotFound", err)
		}
	})

	t.Run("the bypass does not conjure organizations that do not exist", func(t *testing.T) {
		if _, err := svc.ResolveOrganization(ctx, root, "no-such-organization"); !errors.Is(err, ErrNotFound) {
			t.Errorf("superuser resolving a nonexistent organization: got %v, want ErrNotFound", err)
		}
	})

	// A superuser who is a real member of an organization is just a member there. Their
	// actual role applies, and nothing is flagged -- otherwise every ordinary
	// action they took in their own organization would be audited as a bypass, burying
	// the accesses that actually matter.
	t.Run("a superuser who IS a member uses their real role", func(t *testing.T) {
		if _, err := svc.CreateOrganization(ctx, root, "rootcorp", "Root Corp"); err != nil {
			t.Fatalf("superuser creating their own organization: %v", err)
		}

		access, err := svc.ResolveOrganization(ctx, root, "rootcorp")
		if err != nil {
			t.Fatalf("superuser resolving their own organization: %v", err)
		}
		if access.ViaSuperuser {
			t.Error("a superuser acting in their OWN organization was flagged as a bypass")
		}
		// Owner by MEMBERSHIP this time, not by bypass -- so they do hold a role.
		if !hasOwnerRole(access.Roles) {
			t.Errorf("holds %v, want the owner role by membership", roleKeys(access.Roles))
		}
	})

	t.Run("the bypass is audited", func(t *testing.T) {
		if err := svc.RecordSuperuserAccess(ctx, root, acme, "GET", "/api/v1/organizations/acme/members"); err != nil {
			t.Fatalf("record superuser access: %v", err)
		}

		var found bool
		for _, e := range listAudit(t, acme.ID) {
			if e.Action == "superuser.organization_accessed" {
				found = true
			}
		}
		if !found {
			t.Error("no superuser.organization_accessed entry in the organization's audit log")
		}
	})
}

func TestDeactivationIsImmediate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	root := makeSuperuser(t, svc, "root@example.com")
	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}

	token, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login alice: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("alice's fresh token should work: %v", err)
	}

	if _, err := svc.SetUserActive(ctx, root, alice.ID, false); err != nil {
		t.Fatalf("deactivate alice: %v", err)
	}

	// Both halves matter. The session is revoked, so her existing token dies at
	// once rather than lingering for the 30-day TTL...
	if _, _, err := svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a deactivated user's existing session still works: got %v, want ErrUnauthenticated", err)
	}
	// ...and she cannot simply log back in to get a new one.
	if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a deactivated user logged back in: got %v, want ErrInvalidCredentials", err)
	}

	t.Run("reactivation restores login", func(t *testing.T) {
		if _, err := svc.SetUserActive(ctx, root, alice.ID, true); err != nil {
			t.Fatalf("reactivate alice: %v", err)
		}
		if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); err != nil {
			t.Errorf("a reactivated user cannot log in: %v", err)
		}
	})

	// A superuser who deactivates themselves locks the installation's operator
	// out of the only surface that could undo it.
	t.Run("a superuser cannot deactivate themselves", func(t *testing.T) {
		if _, err := svc.SetUserActive(ctx, root, root.ID, false); !errors.Is(err, ErrValidation) {
			t.Errorf("got %v, want ErrValidation", err)
		}
	})
}

func TestSuperuserGrantAndRevoke(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Registration never confers it.
	user, err := svc.repo.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if user.IsSuperuser {
		t.Fatal("a freshly registered user is a superuser")
	}

	granted, err := svc.SetSuperuser(ctx, "alice@example.com", true)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !granted.IsSuperuser {
		t.Error("the grant did not take")
	}

	revoked, err := svc.SetSuperuser(ctx, "alice@example.com", false)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.IsSuperuser {
		t.Error("the revoke did not take")
	}

	t.Run("granting to an unknown email fails", func(t *testing.T) {
		if _, err := svc.SetSuperuser(ctx, "nobody@example.com", true); !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("the grant is audited with a null actor", func(t *testing.T) {
		// The CLI has no logged-in user behind it, so actor_user_id is NULL and
		// organization_id is NULL -- this is an installation-wide act, not an organization one.
		var n int
		err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit_log
			 WHERE action = 'superuser.granted'
			   AND actor_user_id IS NULL
			   AND organization_id IS NULL`).Scan(&n)
		if err != nil {
			t.Fatalf("query audit log: %v", err)
		}
		if n == 0 {
			t.Error("the superuser grant was not audited")
		}
	})
}
