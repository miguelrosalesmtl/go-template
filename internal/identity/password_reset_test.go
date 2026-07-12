package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPasswordResetFlow(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Two live sessions, to prove the reset kills both.
	laptop, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	phone, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := svc.RequestPasswordReset(ctx, "alice@example.com", RequestMeta{}); err != nil {
		t.Fatalf("request reset: %v", err)
	}

	msg := testMailer.lastTo(t, "alice@example.com")
	if !strings.Contains(msg.Body, "https://app.example.test") {
		t.Errorf("the reset link does not use APP_BASE_URL:\n%s", msg.Body)
	}
	token := tokenFromLink(t, msg.Body)

	const newPassword = "an-entirely-different-password"
	if err := svc.ResetPassword(ctx, token, newPassword); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	t.Run("the new password works and the old one does not", func(t *testing.T) {
		if _, _, err := svc.Login(ctx, "alice@example.com", newPassword, RequestMeta{}); err != nil {
			t.Errorf("the new password does not log in: %v", err)
		}
		if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Error("the OLD password still logs in after a reset")
		}
	})

	// THE POINT OF THE WHOLE EXERCISE. If somebody resets their password because
	// they were compromised, and the attacker's session survives it, the reset has
	// achieved exactly nothing.
	t.Run("every existing session is revoked", func(t *testing.T) {
		for name, tok := range map[string]string{"laptop": laptop, "phone": phone} {
			if _, _, err := svc.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("the %s session survived the reset: got %v, want ErrUnauthenticated", name, err)
			}
		}
	})

	t.Run("the token is single-use", func(t *testing.T) {
		err := svc.ResetPassword(ctx, token, "yet-another-password-here")
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("a spent reset token was accepted again: got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("a bogus token is refused", func(t *testing.T) {
		if err := svc.ResetPassword(ctx, "mtt_pwr_nonsense", "yet-another-password-here"); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("a short password is refused", func(t *testing.T) {
		if err := svc.RequestPasswordReset(ctx, "alice@example.com", RequestMeta{}); err != nil {
			t.Fatalf("request reset: %v", err)
		}
		fresh := tokenFromLink(t, testMailer.lastTo(t, "alice@example.com").Body)

		if err := svc.ResetPassword(ctx, fresh, "short"); !errors.Is(err, ErrValidation) {
			t.Errorf("got %v, want ErrValidation", err)
		}
	})

	_ = user
}

// The endpoint is unauthenticated, so an attacker feeds it a list of addresses to
// learn which of them bank with you. It must tell them nothing.
func TestPasswordResetRevealsNothing(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// A real account, an address that has never been seen, and a deactivated user.
	// All three must return nil, and all three must be indistinguishable.
	root := makeSuperuser(t, svc, "root@example.com")
	deactivated, err := svc.Register(ctx, "gone@example.com", goodPassword, "Gone")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.SetUserActive(ctx, root, deactivated.ID, false); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	for _, email := range []string{"alice@example.com", "nobody@example.com", "gone@example.com"} {
		if err := svc.RequestPasswordReset(ctx, email, RequestMeta{}); err != nil {
			t.Errorf("RequestPasswordReset(%q) returned %v; it must return nil for EVERY address, "+
				"or it is an account-enumeration oracle", email, err)
		}
	}

	// Only the real, ACTIVE account gets a reset link. The other two get nothing --
	// though note they may hold a VERIFICATION email from registration, which is why
	// this checks the subject rather than merely the recipient.
	t.Run("only the real, active account gets a reset email", func(t *testing.T) {
		testMailer.mu.Lock()
		defer testMailer.mu.Unlock()

		for _, msg := range testMailer.sent {
			if msg.Subject != "Reset your password" {
				continue
			}
			if msg.To != "alice@example.com" {
				t.Errorf("a password-reset email was sent to %s, which has no usable account", msg.To)
			}
		}
	})

	// The caller learns nothing -- but YOU do. Somebody walking a list of addresses
	// through this endpoint is exactly what the audit log is for.
	t.Run("the rejections are audited even though the caller sees nothing", func(t *testing.T) {
		var n int
		err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit_log
			 WHERE action = 'users.password_reset_rejected'`).Scan(&n)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		if n != 2 {
			t.Errorf("got %d rejected-reset audit entries, want 2 (unknown email + deactivated)", n)
		}
	})
}

// Issuing a new link must kill the old one, and completing a reset must kill every
// other outstanding link -- otherwise an attacker who also requested a reset could
// use their own link to take the account straight back.
func TestOnlyTheNewestResetLinkWorks(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice"); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := svc.RequestPasswordReset(ctx, "alice@example.com", RequestMeta{}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	first := tokenFromLink(t, testMailer.lastTo(t, "alice@example.com").Body)

	if err := svc.RequestPasswordReset(ctx, "alice@example.com", RequestMeta{}); err != nil {
		t.Fatalf("second request: %v", err)
	}
	second := tokenFromLink(t, testMailer.lastTo(t, "alice@example.com").Body)

	if first == second {
		t.Fatal("the two requests produced the same token")
	}

	// The first link is dead. This is what you want if it went to the wrong place.
	if err := svc.ResetPassword(ctx, first, "a-brand-new-password-1"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the SUPERSEDED link still worked: got %v, want ErrInvalidToken", err)
	}
	if err := svc.ResetPassword(ctx, second, "a-brand-new-password-1"); err != nil {
		t.Errorf("the newest link did not work: %v", err)
	}
}

// The invitation token is now emailed and never returned. That is the whole fix:
// an admin could otherwise mint a working link for an address they do not control.
func TestInvitationTokenIsEmailedNotReturned(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)
	memberID := systemRoleID(t, svc, acme.ID, RoleKeyMember)

	inv, err := svc.Invite(ctx, alice, aAccess, "carol@example.com", memberID)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	// The Invitation the API hands back carries no usable credential. TokenHash is
	// json:"-" and there is no plaintext field at all -- the signature does not even
	// have room to return one.
	if inv.Email != "carol@example.com" {
		t.Errorf("invitation is for %q, want carol", inv.Email)
	}

	msg := testMailer.lastTo(t, "carol@example.com")
	if !strings.Contains(msg.Subject, acme.Name) {
		t.Errorf("the invitation subject does not name the tenant: %q", msg.Subject)
	}
	if !strings.Contains(msg.Body, alice.Email) {
		t.Errorf("the invitation body does not say who invited them: %q", msg.Body)
	}

	// And the emailed token is the real one.
	token := tokenFromLink(t, msg.Body)
	carol, err := svc.Register(ctx, "carol@example.com", goodPassword, "Carol")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, carol, token); err != nil {
		t.Fatalf("carol accepting the emailed token: %v", err)
	}
}
