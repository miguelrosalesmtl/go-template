package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// gatedService is a Service with the email-verification gate and the organization cap
// turned ON. The other tests turn both off, because they create organizations constantly
// and are not testing these rules.
func gatedService(t *testing.T, maxOrganizations int) *Service {
	t.Helper()

	newTestService(t) // cleans the database; we build our own service below
	cfg := testAuthSettings()
	cfg.RequireVerifiedEmail = true
	cfg.MaxOrganizationsPerUser = maxOrganizations

	return NewService(
		testPool, cfg,
		settings.Mail{BaseURL: "https://app.example.test"},
		testMailer,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func TestEmailVerification(t *testing.T) {
	svc := gatedService(t, 0)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if alice.IsVerified() {
		t.Fatal("a freshly registered user is already verified")
	}

	// Verification gates ORGANIZATION CREATION, not login. Locking somebody out of their
	// own account because a mail went to spam is a support nightmare for very little
	// gain; stopping an unverified address from standing up organizations is the control
	// that actually matters.
	t.Run("an unverified user can still log in", func(t *testing.T) {
		if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); err != nil {
			t.Errorf("an unverified user cannot log in: %v", err)
		}
	})

	t.Run("but cannot create an organization", func(t *testing.T) {
		if _, err := svc.CreateOrganization(ctx, alice, "acme", "Acme"); !errors.Is(err, ErrEmailNotVerified) {
			t.Errorf("got %v, want ErrEmailNotVerified", err)
		}
	})

	// Registration emailed a link. Click it.
	msg := testMailer.lastTo(t, "alice@example.com")
	if !strings.Contains(msg.Subject, "Confirm") {
		t.Fatalf("registration did not send a verification email (subject %q)", msg.Subject)
	}
	token := tokenFromLink(t, msg.Body)

	verified, err := svc.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verified.IsVerified() {
		t.Fatal("the user is not flagged verified after verifying")
	}

	t.Run("and now they can", func(t *testing.T) {
		if _, err := svc.CreateOrganization(ctx, verified, "acme", "Acme"); err != nil {
			t.Errorf("a verified user cannot create an organization: %v", err)
		}
	})

	t.Run("the link is single-use", func(t *testing.T) {
		if _, err := svc.VerifyEmail(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("a spent verification link worked again: got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("a bogus token is refused", func(t *testing.T) {
		if _, err := svc.VerifyEmail(ctx, "mtt_ver_nonsense"); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("got %v, want ErrInvalidToken", err)
		}
	})
}

// Redeeming an invitation PROVES control of the mailbox it was sent to -- the token
// went there and nowhere else, and AcceptInvitation refuses unless the address
// matches. Demanding a second link afterwards would be theatre.
func TestAcceptingAnInvitationVerifiesTheAddress(t *testing.T) {
	svc := gatedService(t, 0)
	ctx := context.Background()

	// A verified owner, so she can create the organization at all.
	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	alice, err = svc.VerifyEmail(ctx, tokenFromLink(t, testMailer.lastTo(t, "alice@example.com").Body))
	if err != nil {
		t.Fatalf("verify alice: %v", err)
	}
	acme, err := svc.CreateOrganization(ctx, alice, "acme", "Acme")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}

	// Carol registers and does NOT click her verification link.
	carol, err := svc.Register(ctx, "carol@example.com", goodPassword, "Carol")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	if carol.IsVerified() {
		t.Fatal("carol is verified without doing anything")
	}

	aAccess := accessFor(t, svc, alice, acme.Slug)
	memberID := systemRoleID(t, svc, acme.ID, RoleKeyMember)
	if _, err := svc.Invite(ctx, alice, aAccess, "carol@example.com", memberID); err != nil {
		t.Fatalf("invite carol: %v", err)
	}

	invToken := tokenFromLink(t, testMailer.lastTo(t, "carol@example.com").Body)
	if _, err := svc.AcceptInvitation(ctx, carol, invToken); err != nil {
		t.Fatalf("carol accepting: %v", err)
	}

	// She never clicked a verification link -- but she proved control of the mailbox
	// by redeeming a token that was only ever sent there.
	after, err := svc.repo.GetUserByID(ctx, carol.ID)
	if err != nil {
		t.Fatalf("reload carol: %v", err)
	}
	if !after.IsVerified() {
		t.Error("accepting an emailed invitation did not verify the address it was sent to")
	}
}

func TestOrganizationCap(t *testing.T) {
	svc := gatedService(t, 2)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	alice, err = svc.VerifyEmail(ctx, tokenFromLink(t, testMailer.lastTo(t, "alice@example.com").Body))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	for _, slug := range []string{"one", "two"} {
		if _, err := svc.CreateOrganization(ctx, alice, slug, slug); err != nil {
			t.Fatalf("create %s: %v", slug, err)
		}
	}

	// Without a cap, one account stands up unlimited organizations: free storage for an
	// abuser, a bill for you.
	if _, err := svc.CreateOrganization(ctx, alice, "three", "Three"); !errors.Is(err, ErrTooManyOrganizations) {
		t.Errorf("the cap did not hold: got %v, want ErrTooManyOrganizations", err)
	}

	// Deleting one frees a slot -- the cap counts LIVE organizations.
	t.Run("soft-deleting one frees a slot", func(t *testing.T) {
		access := accessFor(t, svc, alice, "one")
		if err := svc.DeleteOrganization(ctx, alice, access); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := svc.CreateOrganization(ctx, alice, "three", "Three"); err != nil {
			t.Errorf("a slot did not free up after a deletion: %v", err)
		}
	})
}

func TestRevokeOneSession(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	laptop, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{UserAgent: "laptop"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	phone, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{UserAgent: "phone"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	sessions, err := svc.ListSessions(ctx, alice.ID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	// Kill the laptop, keep the phone. "Sign out that other device."
	_, laptopSession, err := svc.Authenticate(ctx, laptop)
	if err != nil {
		t.Fatalf("authenticate laptop: %v", err)
	}
	if err := svc.RevokeSession(ctx, alice, laptopSession.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, _, err := svc.Authenticate(ctx, laptop); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the revoked session still works: got %v, want ErrUnauthenticated", err)
	}
	if _, _, err := svc.Authenticate(ctx, phone); err != nil {
		t.Errorf("revoking one session killed another: %v", err)
	}

	// The user id is in the WHERE clause, so you cannot revoke a stranger's session
	// by guessing its id.
	t.Run("cannot revoke somebody else's session", func(t *testing.T) {
		bob, err := svc.Register(ctx, "bob@example.com", goodPassword, "Bob")
		if err != nil {
			t.Fatalf("register bob: %v", err)
		}
		_, phoneSession, err := svc.Authenticate(ctx, phone)
		if err != nil {
			t.Fatalf("authenticate phone: %v", err)
		}

		if err := svc.RevokeSession(ctx, bob, phoneSession.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("bob revoked alice's session: got %v, want ErrNotFound", err)
		}
		if _, _, err := svc.Authenticate(ctx, phone); err != nil {
			t.Errorf("alice's session died anyway: %v", err)
		}
	})
}

func TestPurgeDestroysSoftDeletedOrganizations(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupOrganizationWithOwner(t, svc)
	if err := svc.DeleteOrganization(ctx, alice, accessFor(t, svc, alice, acme.Slug)); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	// Nothing is destroyed yet -- that is the whole meaning of "soft".
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, acme.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatal("a soft-deleted organization was already destroyed")
	}

	t.Run("a zero retention destroys nothing", func(t *testing.T) {
		// The default. Silently shredding a customer's data because a config value
		// had a tidy default is not a decision this template makes.
		purged, err := svc.PurgeDeletedOrganizations(ctx, 0)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if purged != 0 {
			t.Errorf("a zero retention destroyed %d organizations; it must destroy none", purged)
		}
	})

	t.Run("past the retention it is destroyed for real", func(t *testing.T) {
		purged, err := svc.PurgeDeletedOrganizations(ctx, 1*time.Nanosecond)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if purged != 1 {
			t.Fatalf("purged %d organizations, want 1", purged)
		}

		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE id = $1`, acme.ID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Error("the organization survived the purge")
		}

		// And the cascade took its memberships with it -- this IS the right-to-erasure
		// path, so a half-deleted organization would be a failure of the whole point.
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM memberships WHERE organization_id = $1`, acme.ID).Scan(&n); err != nil {
			t.Fatalf("count memberships: %v", err)
		}
		if n != 0 {
			t.Errorf("%d memberships survived the purge of their organization", n)
		}
	})
}
