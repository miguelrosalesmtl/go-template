package identity

import (
	"context"
	"log/slog"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
)

// Email verification.
//
// users.email was always unique and case-insensitive, but nothing checked that the
// person who typed it CONTROLS it. That was tolerable until there was a password
// reset; now it is the foundation the whole account-recovery flow stands on, since
// a reset is only as trustworthy as the mailbox it goes to.
//
// Verification is required to CREATE AN ORGANIZATION. Not to log in -- locking somebody
// out of their own account because a verification email went to spam is a support
// nightmare for very little gain -- but to do the one thing that makes an account
// worth farming: standing up organizations. It doubles as an abuse control.

// SendVerificationEmail mints a verification token and emails it. Called on
// registration, and again on demand.
//
// A failure to send is logged, not returned: registration must not fail because
// the mail provider hiccuped, and the user can always ask for another.
func (s *Service) SendVerificationEmail(ctx context.Context, user User) {
	if user.IsVerified() {
		return // nothing to do
	}

	plaintext, digest, err := auth.NewToken(auth.EmailVerifyTokenPrefix)
	if err != nil {
		s.log.Error("could not mint an email verification token", slog.String("error", err.Error()))
		return
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Only the newest link works, as with password resets.
		if err := repo.InvalidateEmailVerifications(ctx, user.ID); err != nil {
			return err
		}
		return repo.CreateEmailVerification(ctx, user.ID, user.Email, digest,
			time.Now().Add(s.cfg.EmailVerifyTTL))
	})
	if err != nil {
		s.log.Error("could not store an email verification", slog.String("error", err.Error()))
		return
	}

	msg := mail.EmailVerification(s.mailCfg.BaseURL, plaintext, int(s.cfg.EmailVerifyTTL.Hours()))
	msg.To = user.Email

	if err := s.mailer.Send(ctx, msg); err != nil {
		s.log.Error("could not send a verification email",
			slog.String("email", user.Email), slog.String("error", err.Error()))
	}
}

// VerifyEmail spends a verification token and marks the address confirmed.
func (s *Service) VerifyEmail(ctx context.Context, token string) (User, error) {
	var user User

	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Checked and claimed in one UPDATE, so a link cannot be used twice.
		userID, email, err := repo.ConsumeEmailVerification(ctx, auth.HashToken(token))
		if err != nil {
			return err // ErrInvalidToken: unknown, spent, or expired
		}

		user, err = repo.MarkEmailVerified(ctx, userID, email)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionEmailVerified,
			TargetType:  "user",
			TargetID:    userID.String(),
			Metadata:    map[string]any{"email": email},
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// ResendVerification re-sends the verification email for the caller's own address.
func (s *Service) ResendVerification(ctx context.Context, user User) error {
	if user.IsVerified() {
		return invalid("this address is already verified")
	}
	s.SendVerificationEmail(ctx, user)
	return nil
}

// markVerifiedByInvitation confirms an address because the user proved they control
// it -- by redeeming an invitation that was emailed to it.
//
// This is not a shortcut, it is the same proof by a different route. The invitation
// token went to that mailbox and nowhere else, and AcceptInvitation already refuses
// unless the invitation's email matches the caller's. Holding the token IS control
// of the mailbox, so demanding a second email afterwards would be theatre.
//
// It runs inside the caller's transaction.
func markVerifiedByInvitation(ctx context.Context, db database.DB, user User) error {
	if user.IsVerified() {
		return nil
	}

	repo := NewRepository(db)
	if _, err := repo.MarkEmailVerified(ctx, user.ID, user.Email); err != nil {
		return err
	}

	return audit.NewRecorder(db).Record(ctx, audit.Event{
		ActorUserID: &user.ID,
		Action:      audit.ActionEmailVerified,
		TargetType:  "user",
		TargetID:    user.ID.String(),
		Metadata:    map[string]any{"email": user.Email, "via": "invitation"},
	})
}

// CleanupEmailVerifications prunes spent and expired rows. Called by the reaper.
func (s *Service) CleanupEmailVerifications(ctx context.Context, retain time.Duration) (int64, error) {
	return s.repo.DeleteDeadEmailVerifications(ctx, retain)
}

// requireVerifiedEmail is the gate on organization creation.
//
// It is configurable because a project doing its own SSO, or one that verifies out
// of band, has already solved this and should not be told to solve it twice.
func (s *Service) requireVerifiedEmail(user User) error {
	if !s.cfg.RequireVerifiedEmail || user.IsVerified() {
		return nil
	}
	return ErrEmailNotVerified
}
