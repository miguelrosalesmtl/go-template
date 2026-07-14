package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// The superuser staff surface, at /api/v1/admin. Everything here is guarded by
// requireSuperuser and is installation-wide rather than organization-scoped -- these
// are the only handlers in the codebase that legitimately read across organizations.
//
// A non-superuser reaching any of them gets 404, not 403: the staff surface does
// not announce its own existence.

// pageBefore reads the keyset-pagination cursor from ?before=<uuid>. The zero
// UUID means "start at the newest".
func pageBefore(r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return uuid.Nil, true
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, false
	}
	return parsed, true
}

const adminPageSize = 50

// handleAdminListOrganizations lists every organization in the installation, newest first,
// with each one's member count.
func (s *Server) handleAdminListOrganizations(w http.ResponseWriter, r *http.Request) {
	before, ok := pageBefore(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "before must be a UUID")
		return
	}

	organizations, err := s.identity.ListAllOrganizations(r.Context(), before, adminPageSize)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	var next string
	if len(organizations) == adminPageSize {
		next = organizations[len(organizations)-1].Organization.ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": organizations, "next_before": next})
}

// handleAdminListUsers lists every user in the installation, newest first.
func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	before, ok := pageBefore(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "before must be a UUID")
		return
	}

	users, err := s.identity.ListAllUsers(r.Context(), before, adminPageSize)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	var next string
	if len(users) == adminPageSize {
		next = users[len(users)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "next_before": next})
}

type restoreOrganizationRequest struct {
	// Slug is optional. Empty means "the slug it had". Supply one when the original
	// has been claimed by somebody else since the deletion.
	Slug string `json:"slug"`
}

// handleAdminRestoreOrganization brings a soft-deleted organization back.
//
// Superuser only, and it has to be: a deleted organization 404s for its own owners, so
// nobody inside it can ask for it back. This is the support-ticket path -- "we
// deleted our organization by mistake".
//
// Deleting an organization RELEASES its slug, so the original may have been claimed in the
// meantime. If it has, this returns 409 and the caller must supply a new one:
// there is no room for two live organizations on one slug. Restore is always possible; it
// cannot always give you your old URL back.
func (s *Server) handleAdminRestoreOrganization(w http.ResponseWriter, r *http.Request) {
	organizationID, err := uuid.Parse(chi.URLParam(r, "organizationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "organizationID must be a UUID")
		return
	}

	var req restoreOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	organization, err := s.identity.RestoreOrganization(r.Context(), userFrom(r.Context()), organizationID, req.Slug)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, organization)
}

type setUserActiveRequest struct {
	IsActive bool `json:"is_active"`
}

// handleAdminSetUserActive activates or deactivates a user account.
//
// Deactivating also revokes every session the user holds, in the same
// transaction, so the lockout takes effect on their next request rather than
// whenever their 30-day token happens to expire.
//
// Note what is NOT here: any way to set is_superuser. That is deliberate -- if a
// superuser could promote another over HTTP, one stolen superuser token could
// mint permanent backdoor accounts. Granting it requires the CLI, and therefore
// database access. See `server grant-superuser`.
func (s *Server) handleAdminSetUserActive(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "userID must be a UUID")
		return
	}

	var req setUserActiveRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.identity.SetUserActive(r.Context(), userFrom(r.Context()), targetID, req.IsActive)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}
