package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// maxBodyBytes caps a request body. Without it, a caller can stream gigabytes at
// the JSON decoder and exhaust the process's memory -- a denial of service that
// costs the attacker nothing.
const maxBodyBytes = 1 << 20 // 1 MiB

// writeJSON serialises v with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// errorBody is the one error shape this API returns, so a client can rely on it.
type errorBody struct {
	Error string `json:"error"`
}

// writeError sends a JSON error envelope.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// decodeJSON reads a JSON request body into dst, rejecting unknown fields.
//
// DisallowUnknownFields turns a typo'd field name into a 400 rather than a
// silently ignored value -- the difference between a caller learning that
// {"rol": "owner"} did nothing, and their believing it set a role.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}
	// A second value in the body means the caller sent something we do not
	// understand; refuse rather than silently using only the first.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("body must contain a single JSON object")
	}
	return nil
}

// errorHandler maps service errors onto HTTP responses, and records the ones that
// are refusals to the audit log.
//
// Every handler funnels its errors through here, so the mapping from a domain
// error to a status code is defined once and cannot drift between endpoints -- and
// so there is exactly one place that sees every denial in the application.
//
// THIS IS WHY DENIALS ARE RECORDED HERE AND NOT IN THE SERVICE. A refusal aborts
// its transaction. An audit entry written inside that transaction would be rolled
// back along with the very failure it was recording, leaving no trace of precisely
// the events you most want to see. The error handler runs after the rollback, on
// the pool, so the record survives.
type errorHandler struct {
	log   *slog.Logger
	debug bool
	pool  *pgxpool.Pool
}

// handle writes the response for err, and audits it if it was a denial. It returns
// nothing: the request is over.
func (h errorHandler) handle(w http.ResponseWriter, r *http.Request, err error) {
	h.auditDenial(r, err)

	switch {
	case errors.Is(err, identity.ErrUnauthenticated):
		// The WWW-Authenticate header is what tells a client this is a missing or
		// stale credential rather than a permissions problem.
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
		writeError(w, http.StatusUnauthorized, "authentication required")

	case errors.Is(err, identity.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid email or password")

	case errors.Is(err, identity.ErrForbidden):
		writeError(w, http.StatusForbidden, "you do not have permission to do that")

	case errors.Is(err, identity.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")

	case errors.Is(err, identity.ErrEmailTaken):
		writeError(w, http.StatusConflict, "that email is already registered")

	case errors.Is(err, identity.ErrSlugTaken):
		writeError(w, http.StatusConflict, "that organization slug is already taken")

	case errors.Is(err, identity.ErrAlreadyMember):
		writeError(w, http.StatusConflict, "that user is already a member of this organization")

	case errors.Is(err, identity.ErrLastOwner):
		writeError(w, http.StatusConflict, "an organization must always have at least one owner")

	case errors.Is(err, identity.ErrEscalation):
		// 403, and the message names the permissions the caller lacked. A bare
		// "forbidden" here is how an admin ends up filing a bug about a role editor
		// that mysteriously refuses to save.
		writeError(w, http.StatusForbidden, err.Error())

	case errors.Is(err, identity.ErrSystemRole):
		writeError(w, http.StatusForbidden,
			"the owner, admin, and member roles are built in and cannot be changed -- create a custom role instead")

	case errors.Is(err, identity.ErrRoleInUse):
		writeError(w, http.StatusConflict,
			"this role is still assigned to members -- reassign them before deleting it")

	case errors.Is(err, identity.ErrRoleKeyTaken):
		writeError(w, http.StatusConflict, "a role with that key already exists in this organization")

	case errors.Is(err, identity.ErrNoRoles):
		writeError(w, http.StatusBadRequest,
			"a member must hold at least one role -- remove them from the organization instead")

	case errors.Is(err, identity.ErrInvitationInvalid):
		writeError(w, http.StatusBadRequest, "this invitation is invalid or has expired")

	case errors.Is(err, identity.ErrInvalidToken):
		writeError(w, http.StatusBadRequest, "this link is invalid or has expired -- request a new one")

	case errors.Is(err, identity.ErrRateLimited):
		// Retry-After was already set by the limiter middleware.
		writeError(w, http.StatusTooManyRequests, "too many attempts -- try again shortly")

	case errors.Is(err, identity.ErrEmailNotVerified):
		// 403 with an actionable message: the caller can fix this themselves, and
		// telling them how is the difference between a support ticket and a click.
		writeError(w, http.StatusForbidden,
			"verify your email address first -- POST /api/v1/auth/email/verify/resend to get a new link")

	case errors.Is(err, identity.ErrTooManyOrganizations):
		writeError(w, http.StatusConflict, "you have reached the maximum number of organizations")

	case errors.Is(err, identity.ErrMailFailed):
		// 502, not 500, and not 201. The thing WAS created -- the invitation exists
		// and is in the database -- but the email announcing it did not go out. Say
		// exactly that, so the admin resends rather than re-inviting and piling up
		// dead tokens.
		writeError(w, http.StatusBadGateway,
			"created, but the email could not be sent -- check your mail configuration and resend")

	case errors.Is(err, identity.ErrValidation):
		// The message is safe to echo: validation errors are written for the
		// caller, and say nothing about our internals.
		writeError(w, http.StatusBadRequest, err.Error())

	default:
		// Anything unrecognised is our bug. Log it with the request ID so it can
		// be found, and tell the caller nothing: an internal error string can
		// carry table names, query fragments, or file paths.
		h.log.Error("unhandled error",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("error", err.Error()),
		)
		if h.debug {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

// auditDenial records the refusals worth knowing about.
//
// Without these, an attacker probing which permissions they have, or working
// through an invitation-token guess list, produces NO record at all -- and an
// empty audit log reads exactly like "nothing happened". Successes alone make a
// change-history; it is the denials that make it a security trail.
//
// Failed LOGINS are recorded in the identity service instead, because only it
// knows which email was tried and why it failed.
//
// Best-effort: a failure to write the audit entry is logged and swallowed. Turning
// a clean 403 into a 500 because the audit table hiccuped would be a worse outcome
// than losing the entry.
func (h errorHandler) auditDenial(r *http.Request, err error) {
	var action audit.Action
	metadata := map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
	}

	switch {
	case errors.Is(err, identity.ErrEscalation):
		// The RBAC guard firing: somebody tried to grant a permission they do not
		// hold. This one is rarely innocent.
		action = audit.ActionEscalationDenied
		metadata["detail"] = err.Error() // names the permissions they lacked

	case errors.Is(err, identity.ErrForbidden):
		// A 403 from requirePermission, or from the owner-protection rules.
		action = audit.ActionAccessDenied

	case errors.Is(err, identity.ErrInvitationInvalid):
		// A bad, spent, expired, or misaddressed invitation token -- including
		// somebody trying to redeem a link that was never theirs.
		action = audit.ActionInvitationRejected

	case errors.Is(err, identity.ErrRateLimited):
		// One is noise. A stream of them from one IP is an attack in progress, and
		// this is the only place you would ever see the difference.
		action = audit.ActionRateLimited

	default:
		// Everything else is either a success, a validation error, or our own bug.
		// None of them belong in a security trail.
		return
	}

	event := audit.Event{Action: action, Metadata: metadata}

	// The request may have failed before authentication, or before the organization was
	// resolved, so neither is assumed. An unattributed denial is still worth
	// recording -- often more so.
	if user, ok := tryUserFrom(r.Context()); ok {
		event.ActorUserID = &user.ID
		metadata["email"] = user.Email
	}
	if access, ok := tryAccessFrom(r.Context()); ok {
		event.OrganizationID = &access.Organization.ID
		event.TargetType = "organization"
		event.TargetID = access.Organization.ID.String()
	}

	// On the POOL, never in a transaction -- see the type comment. The request's
	// own transaction, if it had one, has already been rolled back.
	//
	// context.WithoutCancel: if the client disconnected, r.Context() is already
	// cancelled, and the record of why we refused them would be the one thing we
	// failed to write.
	ctx := context.WithoutCancel(r.Context())
	if err := audit.NewRecorder(h.pool).Record(ctx, event); err != nil {
		h.log.Error("could not audit a denial",
			slog.String("action", string(action)),
			slog.String("error", err.Error()),
		)
	}

	// ALSO emit it as a log line, at WARN, with a stable `security_event` key.
	//
	// The audit table is the record; the LOG is what your alerting can actually see.
	// Every shop already ships logs somewhere that can match on a field and page
	// somebody -- and nobody wants to point their alerting at a Postgres table.
	//
	// So: alert on `security_event`. The README lists the rules worth writing.
	attrs := []any{
		slog.String("security_event", string(action)),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if event.ActorUserID != nil {
		attrs = append(attrs, slog.String("user_id", event.ActorUserID.String()))
	}
	if event.OrganizationID != nil {
		attrs = append(attrs, slog.String("organization_id", event.OrganizationID.String()))
	}
	h.log.Warn("security event", attrs...)
}
