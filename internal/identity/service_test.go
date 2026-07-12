package identity

import (
	"context"
	"errors"
	"testing"
)

const goodPassword = "correct-horse-battery"

func TestRegisterAndLogin(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "Alice@Example.COM ", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Emails are normalised on the way in, so "Alice@Example.COM" and
	// "alice@example.com" are the same account and not two.
	if user.Email != "alice@example.com" {
		t.Errorf("stored email is %q, want it lowercased and trimmed", user.Email)
	}
	// The hash must never escape the process.
	if user.PasswordHash == "" {
		t.Error("the user's password hash was not set")
	}

	t.Run("duplicate email is rejected", func(t *testing.T) {
		if _, err := svc.Register(ctx, "alice@example.com", goodPassword, ""); !errors.Is(err, ErrEmailTaken) {
			t.Errorf("got %v, want ErrEmailTaken", err)
		}
		// Including under different capitalisation -- citext is what guarantees it.
		if _, err := svc.Register(ctx, "ALICE@EXAMPLE.COM", goodPassword, ""); !errors.Is(err, ErrEmailTaken) {
			t.Errorf("got %v, want ErrEmailTaken for a differently-cased duplicate", err)
		}
	})

	t.Run("login issues a usable token", func(t *testing.T) {
		token, got, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if token == "" {
			t.Fatal("login returned an empty token")
		}
		if got.ID != user.ID {
			t.Errorf("login returned user %s, want %s", got.ID, user.ID)
		}

		authed, session, err := svc.Authenticate(ctx, token)
		if err != nil {
			t.Fatalf("authenticate with the token just issued: %v", err)
		}
		if authed.ID != user.ID {
			t.Errorf("the token authenticated as %s, want %s", authed.ID, user.ID)
		}
		if session.UserID != user.ID {
			t.Errorf("the session belongs to %s, want %s", session.UserID, user.ID)
		}
	})

	t.Run("login is case-insensitive in the email", func(t *testing.T) {
		if _, _, err := svc.Login(ctx, "ALICE@example.com", goodPassword, RequestMeta{}); err != nil {
			t.Errorf("login with a differently-cased email: %v", err)
		}
	})

	// A wrong password, an unknown email, and (below) a deactivated account must
	// all give back the identical error. Any difference is an oracle for
	// enumerating which emails have accounts.
	t.Run("bad credentials are indistinguishable", func(t *testing.T) {
		_, _, wrongPass := svc.Login(ctx, "alice@example.com", "not-her-password", RequestMeta{})
		_, _, noSuchUser := svc.Login(ctx, "nobody@example.com", goodPassword, RequestMeta{})

		if !errors.Is(wrongPass, ErrInvalidCredentials) {
			t.Errorf("wrong password: got %v, want ErrInvalidCredentials", wrongPass)
		}
		if !errors.Is(noSuchUser, ErrInvalidCredentials) {
			t.Errorf("unknown email: got %v, want ErrInvalidCredentials", noSuchUser)
		}
		if wrongPass.Error() != noSuchUser.Error() {
			t.Errorf("the two errors differ (%q vs %q): this leaks which emails are registered",
				wrongPass, noSuchUser)
		}
	})
}

func TestLogoutRevokesOnlyThatSession(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	laptop, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{UserAgent: "laptop"})
	if err != nil {
		t.Fatalf("login on the laptop: %v", err)
	}
	phone, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{UserAgent: "phone"})
	if err != nil {
		t.Fatalf("login on the phone: %v", err)
	}

	if err := svc.Logout(ctx, laptop, user.ID); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if _, _, err := svc.Authenticate(ctx, laptop); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the logged-out token still works: got %v, want ErrUnauthenticated", err)
	}
	// Signing out of the laptop must not sign you out of the phone.
	if _, _, err := svc.Authenticate(ctx, phone); err != nil {
		t.Errorf("logging out on one device killed the session on another: %v", err)
	}
}

// The whole reason for DB-backed sessions over JWTs: revocation is immediate.
func TestChangePasswordRevokesEverySession(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	first, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	second, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	const newPassword = "an-entirely-different-password"
	if err := svc.ChangePassword(ctx, user.ID, goodPassword, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}

	// Both sessions -- including the one that made the request -- are now dead.
	// A password change that left a stolen session alive would have achieved
	// nothing, which is the entire point.
	for name, token := range map[string]string{"first": first, "second": second} {
		if _, _, err := svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("the %s session survived the password change: got %v, want ErrUnauthenticated", name, err)
		}
	}

	if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("the old password still logs in")
	}
	if _, _, err := svc.Login(ctx, "alice@example.com", newPassword, RequestMeta{}); err != nil {
		t.Errorf("the new password does not log in: %v", err)
	}

	t.Run("the wrong current password is refused", func(t *testing.T) {
		err := svc.ChangePassword(ctx, user.ID, "not-the-current-password", "yet-another-password")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("got %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestCreateTenantMakesTheCreatorOwner(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	tenant, err := svc.CreateTenant(ctx, alice, "acme", "Acme Inc")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// The tenant and the owning membership are created in one transaction; a
	// tenant with no owner would be unadministrable by anyone, including its
	// creator.
	access, err := svc.ResolveTenant(ctx, alice, tenant.Slug)
	if err != nil {
		t.Fatalf("the creator cannot resolve their own tenant: %v", err)
	}
	if !hasOwnerRole(access.Roles) {
		t.Errorf("the creator holds %v, want the owner role", roleKeys(access.Roles))
	}
	// The owner role carries every permission in the catalog, so the creator can
	// do anything in their own tenant.
	if !access.Permissions.Superset(AllPermissions()) {
		t.Errorf("the owner lacks %v", access.Permissions.Missing(AllPermissions()))
	}
	if access.ViaSuperuser {
		t.Error("a genuine member must not be flagged as a superuser bypass")
	}

	t.Run("a duplicate slug is rejected", func(t *testing.T) {
		if _, err := svc.CreateTenant(ctx, alice, "acme", "Acme Again"); !errors.Is(err, ErrSlugTaken) {
			t.Errorf("got %v, want ErrSlugTaken", err)
		}
	})

	t.Run("invalid slugs are rejected", func(t *testing.T) {
		for _, slug := range []string{
			"",           // empty
			"a",          // too short
			"acme corp",  // space
			"acme_corp",  // underscore
			"-acme",      // leading hyphen
			"acme-",      // trailing hyphen
			"acme--corp", // double hyphen
			"api",        // reserved: would collide with a route
			"admin",      // reserved
		} {
			if _, err := svc.CreateTenant(ctx, alice, slug, "Name"); !errors.Is(err, ErrValidation) {
				t.Errorf("slug %q: got %v, want ErrValidation", slug, err)
			}
		}
	})

	// Case and surrounding space are normalised away rather than rejected: the
	// slug goes into a URL, and "Globex " is obviously meant to be "globex".
	t.Run("slugs are normalised, not rejected, for case and space", func(t *testing.T) {
		tenant, err := svc.CreateTenant(ctx, alice, "  GlobEx  ", "Globex Corp")
		if err != nil {
			t.Fatalf("create tenant with a messy slug: %v", err)
		}
		if tenant.Slug != "globex" {
			t.Errorf("slug is %q, want it lowercased and trimmed to %q", tenant.Slug, "globex")
		}
	})
}
