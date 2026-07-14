package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// Handlers are deliberately thin: decode, call the service, encode. Every rule
// worth testing lives in internal/identity, so none of it has to be re-tested
// through HTTP, and a future gRPC or CLI front end gets the same behaviour free.

// ---------------------------------------------------------------- auth

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

// handleRegister creates a global user account. It does not log them in.
//
// This endpoint necessarily discloses whether an email is registered (it must
// 409 on a duplicate). Rate-limit it in front of the app -- see the README.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.identity.Register(r.Context(), req.Email, req.Password, req.FullName)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	// Token is shown exactly once. The server keeps only its hash and cannot
	// reproduce it; a client that loses it must log in again.
	Token string        `json:"token"`
	User  identity.User `json:"user"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	token, user, err := s.identity.Login(r.Context(), req.Email, req.Password, s.requestMeta(r))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{Token: token, User: user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r.Context())

	// Revoke the exact token this request presented, not every session the user
	// has: logging out of a laptop should not sign you out of your phone.
	if err := s.identity.Logout(r.Context(), bearerToken(r), user.ID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r.Context()))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleChangePassword rotates the password and signs the user out everywhere --
// including this session. The client must log in again with the new password.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user := userFrom(r.Context())
	if err := s.identity.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r.Context())
	current := sessionFrom(r.Context())

	sessions, err := s.identity.ListSessions(r.Context(), user.ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	// Flag the session making this request, so a UI can label it "this device"
	// and avoid inviting the user to revoke the session they are using.
	type sessionView struct {
		identity.Session
		Current bool `json:"current"`
	}
	views := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		views = append(views, sessionView{Session: sess, Current: sess.ID == current.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// ---------------------------------------------------------------- organizations

func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r.Context())

	organizations, err := s.identity.ListOrganizations(r.Context(), user.ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": organizations})
}

type createOrganizationRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// handleCreateOrganization creates an organization with the caller as its owner.
func (s *Server) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req createOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	organization, err := s.identity.CreateOrganization(r.Context(), userFrom(r.Context()), req.Slug, req.Name)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, organization)
}

// handleGetOrganization returns the organization in the path along with the caller's
// authority in it. requireOrganization has already established that authority, so
// there is nothing left to check here.
//
// It returns the whole OrganizationAccess, not just the organization and roles, so that
// permissions and via_superuser reach the client. A UI needs the permission set to
// decide which buttons to show, and should use via_superuser to display a
// conspicuous "you are here as an operator, not a member" banner -- an operator who
// forgets which hat they are wearing is how accidents happen.
func (s *Server) handleGetOrganization(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, accessFrom(r.Context()))
}

type updateOrganizationRequest struct {
	Name string `json:"name"`
}

// handleUpdateOrganization renames the organization.
//
// The NAME is the only thing that can change. A body containing "slug" is rejected
// with a 400 by decodeJSON's DisallowUnknownFields -- the slug is an identifier
// living in every URL, bookmark, saved API call, and webhook config your customers
// have, and quietly changing it would break all of them. The name is the label,
// and the label is what people actually want to fix.
func (s *Server) handleUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	var req updateOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest,
			"invalid JSON body (note: the organization slug is immutable; only the name can be changed)")
		return
	}

	ctx := r.Context()
	organization, err := s.identity.UpdateOrganization(ctx, userFrom(ctx), accessFrom(ctx), req.Name)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, organization)
}

// handleDeleteOrganization soft-deletes the organization. Requires organization.delete, which only
// the owner role carries.
//
// The organization becomes invisible to EVERYONE immediately -- including the owner who
// just deleted it, who will find it gone from their organization list and 404 on its
// URL. Nothing is destroyed; a superuser can restore it whole. The slug is released
// for anyone else to claim, which is the one thing a restore may not be able to
// undo.
func (s *Server) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := s.identity.DeleteOrganization(ctx, userFrom(ctx), accessFrom(ctx)); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- members

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	members, err := s.identity.ListMembers(r.Context(), organizationFrom(r.Context()).ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// Changing a member's roles lives in handlers_roles.go -- it is a role operation,
// and the escalation guard in the service is what makes it safe.

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "userID must be a UUID")
		return
	}

	ctx := r.Context()
	if err := s.identity.RemoveMember(ctx, userFrom(ctx), accessFrom(ctx), targetID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLeaveOrganization removes the caller from the organization.
//
// It needs no permission -- any member may walk out, and requiring members.remove
// to leave would trap a plain member in an organization forever. The last-owner rule
// still applies, so the sole owner gets a 409 telling them to appoint a successor
// first.
func (s *Server) handleLeaveOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := userFrom(ctx)

	if err := s.identity.RemoveMember(ctx, user, accessFrom(ctx), user.ID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- invitations

type createInvitationRequest struct {
	Email string `json:"email"`
	// RoleID is the role the invitee will hold on joining. It must be a role this
	// organization can see -- a system role, or one of its own -- and the caller must
	// hold every permission it carries. Both are enforced in the service.
	RoleID uuid.UUID `json:"role_id"`
}

// handleCreateInvitation issues an invitation and EMAILS it.
//
// The response deliberately does NOT contain the token. It used to, which was a
// hole: an admin could mint a working invitation link for carol@example.com, keep
// it, and redeem it themselves by registering that address. The only copy now goes
// to the invitee's inbox.
//
// In development (MAIL_BACKEND=log) that "inbox" is the application log, so the
// link is in `docker compose logs app`. Startup refuses that backend in production.
func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	var req createInvitationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.RoleID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "role_id is required -- GET /roles to list the roles you can offer")
		return
	}

	ctx := r.Context()
	inv, err := s.identity.Invite(ctx, userFrom(ctx), accessFrom(ctx), req.Email, req.RoleID)
	if err != nil {
		// ErrMailFailed is special: the invitation EXISTS, the email did not send.
		// The error handler turns it into a 502 saying exactly that, so the admin
		// resends instead of re-inviting and piling up dead tokens.
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	invitations, err := s.identity.ListInvitations(r.Context(), organizationFrom(r.Context()).ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID, err := uuid.Parse(chi.URLParam(r, "invitationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invitationID must be a UUID")
		return
	}

	ctx := r.Context()
	if err := s.identity.RevokeInvitation(ctx, userFrom(ctx), organizationFrom(ctx), invitationID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type acceptInvitationRequest struct {
	Token string `json:"token"`
}

// handleAcceptInvitation joins the caller to the organization that invited them.
//
// It sits outside /organizations/{organization} on purpose: the caller is not a member yet,
// so requireOrganization would 404 them before they ever got here. The organization comes
// from the invitation token, not from the URL.
func (s *Server) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req acceptInvitationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	organization, err := s.identity.AcceptInvitation(r.Context(), userFrom(r.Context()), req.Token)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, organization)
}

// ---------------------------------------------------------------- audit

// auditPageSize is how many entries one page of the audit log holds.
const auditPageSize = 50

// handleListAuditLog returns the organization's activity, newest first, with filters.
//
//	?action=roles.created     one exact action
//	?actor=<user uuid>        everything one person did
//	?from=2026-01-01T00:00:00Z&to=...   a time window (RFC 3339)
//	?before=<entry uuid>      the next page
//
// The filters are not decoration. Pagination alone is useless once the log has
// 100k rows in it: "did anybody touch roles last March" is not a question you can
// answer by scrolling, and an audit log you cannot query is an audit log nobody
// reads.
//
// Pagination is keyset. Because ids are uuidv7 and therefore time-ordered,
// "id < before" means "older than" -- so a page is an index walk with no sort,
// page 100 costs what page 1 costs, and a row arriving mid-scroll cannot shift the
// pages under the reader. OFFSET fails all three.
func (s *Server) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := audit.Filter{Limit: auditPageSize, Action: audit.Action(q.Get("action"))}

	if raw := q.Get("before"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be a UUID")
			return
		}
		filter.Before = parsed
	}

	if raw := q.Get("actor"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "actor must be a user UUID")
			return
		}
		filter.ActorUserID = &parsed
	}

	for _, f := range []struct {
		name string
		dest *time.Time
	}{
		{"from", &filter.From},
		{"to", &filter.To},
	} {
		if raw := q.Get(f.name); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, f.name+" must be an RFC 3339 timestamp")
				return
			}
			*f.dest = parsed
		}
	}

	entries, err := audit.NewRecorder(s.pool).List(r.Context(), organizationFrom(r.Context()).ID, filter)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	// The cursor for the next page is the last id on this one; absent when the
	// page was not full, which means there is nothing more to fetch.
	var next string
	if len(entries) == auditPageSize {
		next = entries[len(entries)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "next_before": next})
}

// handleRevokeSession signs one device out.
//
// The service puts the caller's user id in the WHERE clause, so this cannot revoke
// anybody else's session even with a guessed id.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "sessionID must be a UUID")
		return
	}

	if err := s.identity.RevokeSession(r.Context(), userFrom(r.Context()), sessionID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
