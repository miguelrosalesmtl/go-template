package identity

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
)

// Password reset. Structurally this is the invitation flow again -- a random
// token, stored only as its digest, single-use and short-lived -- but the threat
// model is different in one important way: an ATTACKER is the one who triggers it,
// against an account they do not own, to see what happens.
//
// So the whole flow is built to tell them nothing.

// RequestPasswordReset emails a reset link, if the email belongs to an account.
//
// IT ALWAYS RETURNS NIL. Not on success -- on EVERYTHING. An unknown email, a
// deactivated account, an SSO-only user with no password: all of them look
// identical to the caller, because the alternative is a free account-enumeration
// oracle sitting on an unauthenticated endpoint. "We have sent you a link if that
// address has an account" is the only thing the API may say.
//
// The errors that a caller must not see are still LOGGED and AUDITED, because you
// very much want to know that somebody is walking a list of addresses through this
// endpoint.
func (s *Service) RequestPasswordReset(ctx context.Context, email string, meta RequestMeta) error {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if isNotFound(err) {
			// No such account. Say nothing, but record the attempt -- a burst of
			// these from one IP is somebody enumerating.
			s.recordResetRequest(ctx, nil, email, "unknown_email")
			return nil
		}
		// A real database failure. The caller still learns nothing.
		s.log.Error("password reset lookup failed", slog.String("error", err.Error()))
		return nil
	}

	switch {
	case !user.IsActive:
		s.recordResetRequest(ctx, &user.ID, email, "deactivated")
		return nil
	case user.PasswordHash == "":
		// An SSO-only account has no password to reset, and giving it one here would
		// quietly create a second way in.
		s.recordResetRequest(ctx, &user.ID, email, "no_password_set")
		return nil
	}

	plaintext, digest, err := auth.NewToken(auth.PasswordResetTokenPrefix)
	if err != nil {
		s.log.Error("could not mint a password reset token", slog.String("error", err.Error()))
		return nil
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Issuing a new link invalidates any older one. If the first went to the
		// wrong place, or the user clicked "forgot password" three times, only the
		// newest may be used.
		if err := repo.InvalidatePasswordResets(ctx, user.ID); err != nil {
			return err
		}

		if err := repo.CreatePasswordReset(ctx, user.ID, digest,
			time.Now().Add(s.cfg.PasswordResetTTL), meta.IPAddress, meta.UserAgent); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionPasswordResetRequested,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": email},
		})
	})
	if err != nil {
		s.log.Error("could not store a password reset", slog.String("error", err.Error()))
		return nil
	}

	// Send AFTER the commit. The other order would email a link that does not exist
	// yet, and could email one that never comes to exist if the transaction then
	// rolled back.
	msg := mail.PasswordReset(s.mailCfg.BaseURL, plaintext, int(s.cfg.PasswordResetTTL.Hours()))
	msg.To = email

	if err := s.mailer.Send(ctx, msg); err != nil {
		// The token is committed and the user is expecting an email that will not
		// arrive. Nothing useful to tell them -- saying "we could not send it"
		// would confirm the account exists.
		s.log.Error("could not send a password reset email",
			slog.String("email", email), slog.String("error", err.Error()))
	}
	return nil
}

// recordResetRequest audits a reset request that will NOT result in an email --
// unknown address, deactivated account, SSO-only user.
//
// These are the interesting ones. A legitimate user's reset request is noise; a
// hundred requests for a hundred addresses that do not exist is somebody probing
// which of them do.
func (s *Service) recordResetRequest(ctx context.Context, userID *uuid.UUID, email, reason string) {
	err := audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		ActorUserID: userID,
		Action:      audit.ActionPasswordResetRejected,
		TargetType:  "user",
		Metadata:    map[string]any{"email": email, "reason": reason},
	})
	if err != nil {
		s.log.Error("could not audit a rejected password reset", slog.String("error", err.Error()))
	}
}

// ResetPassword spends a reset token and sets a new password.
//
// Three things happen together, and all three must: the password changes, EVERY
// session the user holds is revoked, and every other outstanding reset link is
// spent.
//
// The session revocation is the point of the whole exercise. If somebody reset
// their password because their account was compromised, and the attacker's session
// stayed alive, the reset achieved precisely nothing.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// The token's validity is checked and claimed in one UPDATE, so two
		// concurrent uses of the same link cannot both succeed.
		userID, err := repo.ConsumePasswordReset(ctx, auth.HashToken(token))
		if err != nil {
			return err // ErrInvalidToken: unknown, spent, or expired -- indistinguishable
		}

		if err := repo.UpdateUserPassword(ctx, userID, hash); err != nil {
			return err
		}

		revoked, err := repo.RevokeUserSessions(ctx, userID)
		if err != nil {
			return err
		}

		// Any OTHER outstanding link is now dead too. Otherwise an attacker who had
		// also requested a reset could use their own link to take the account
		// straight back.
		if err := repo.InvalidatePasswordResets(ctx, userID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionPasswordReset,
			TargetType:  "user",
			TargetID:    userID.String(),
			Metadata:    map[string]any{"sessions_revoked": revoked},
		})
	})
}

// CleanupPasswordResets prunes spent and expired rows. Called by the reaper.
func (s *Service) CleanupPasswordResets(ctx context.Context, retain time.Duration) (int64, error) {
	return s.repo.DeleteDeadPasswordResets(ctx, retain)
}
