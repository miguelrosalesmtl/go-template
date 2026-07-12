package server

import (
	"net/http"
)

// Password reset. The two endpoints are unauthenticated -- the whole point is that
// the user cannot log in -- which is exactly why both are rate limited and why the
// first one is so careful about what it says.

type requestPasswordResetRequest struct {
	Email string `json:"email"`
}

// handleRequestPasswordReset emails a reset link.
//
// IT ALWAYS RETURNS 204. Not "204 if the account exists, 404 otherwise" -- 204,
// always, for an unknown address, a deactivated account, an SSO-only user, and a
// database failure alike.
//
// Anything else is a free account-enumeration oracle on an unauthenticated
// endpoint: an attacker feeds it a list of a million addresses and learns which of
// them bank with you. The service records which case it really was, in the audit
// log, where the attacker cannot see it and you can.
//
// The client should say "if that address has an account, we've sent a link" -- which
// is both the honest thing and the only thing this endpoint knows.
func (s *Server) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req requestPasswordResetRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// The error is deliberately discarded: RequestPasswordReset returns nil for
	// everything except a programming mistake, precisely so this handler cannot
	// accidentally leak the difference.
	_ = s.identity.RequestPasswordReset(r.Context(), req.Email, s.requestMeta(r))

	w.WriteHeader(http.StatusNoContent)
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// handleResetPassword spends a reset token and sets the new password.
//
// It also revokes every session the user has -- see Service.ResetPassword. If they
// are resetting because they were compromised, leaving the attacker's session alive
// would make the whole exercise pointless.
//
// The user must then log in with the new password. That is deliberate: it proves
// the reset worked, and it means this endpoint never issues a credential, so a
// stolen reset link cannot be turned straight into a session without the attacker
// also choosing (and therefore revealing, on the next login attempt) a new password.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	if err := s.identity.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- email verification

type verifyEmailRequest struct {
	Token string `json:"token"`
}

// handleVerifyEmail spends a verification token and confirms the address.
//
// Public, because the user clicks the link from their inbox and may well not have a
// session in that browser -- requiring one would make the link useless on a phone.
func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	user, err := s.identity.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// handleResendVerification re-sends the caller's own verification email.
//
// Authenticated, and it can only ever target the caller's own address -- there is no
// parameter for anyone else's. An unauthenticated "resend to this address" endpoint
// would be a free way to mail-bomb a stranger.
func (s *Server) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	if err := s.identity.ResendVerification(r.Context(), userFrom(r.Context())); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
