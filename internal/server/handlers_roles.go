package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// The role-management API: the configurable half of RBAC.
//
// These handlers are thin, as ever -- but note what they do NOT do. None of them
// checks whether the caller may hand out the permissions they are asking for.
// That is the escalation guard, and it lives in the service (checkEscalation),
// because it must hold for every caller of the rules, not merely for HTTP ones.

// handleListPermissions returns the permission catalog: every permission this
// build enforces, with its description.
//
// This is the list a role editor renders as checkboxes. Because it comes from the
// Go Catalog rather than from a table someone can write to, a UI can never offer
// a permission that no code checks -- which is the failure mode the whole
// permissions-are-code design exists to prevent.
func (s *Server) handleListPermissions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"permissions": identity.Catalog})
}

// handleListRoles returns the roles this organization can use: the three system roles,
// which every organization shares, plus its own custom ones.
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.identity.ListRoles(r.Context(), organizationFrom(r.Context()).ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

type roleRequest struct {
	Key         string                `json:"key"`
	Name        string                `json:"name"`
	Permissions []identity.Permission `json:"permissions"`
}

// handleCreateRole builds a custom role for this organization.
//
// Requires roles.manage AND -- enforced in the service -- that the caller already
// holds every permission they are putting into the new role. Otherwise roles.manage
// would just be a long-winded way of spelling "owner".
func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	role, err := s.identity.CreateRole(ctx, userFrom(ctx), accessFrom(ctx), req.Key, req.Name, req.Permissions)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

type updateRoleRequest struct {
	Name        string                `json:"name"`
	Permissions []identity.Permission `json:"permissions"`
}

// handleUpdateRole renames a custom role and replaces its permission set.
//
// The key is immutable: it is the stable identifier a role is known by, and
// letting it change would silently repoint anything that referenced it.
func (s *Server) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "roleID must be a UUID")
		return
	}

	var req updateRoleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	role, err := s.identity.UpdateRole(ctx, userFrom(ctx), accessFrom(ctx), roleID, req.Name, req.Permissions)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

// handleDeleteRole removes a custom role. It 409s while anyone still holds it:
// reassign them first, because deleting a role should not strip somebody's access
// as an invisible side effect.
func (s *Server) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "roleID must be a UUID")
		return
	}

	ctx := r.Context()
	if err := s.identity.DeleteRole(ctx, userFrom(ctx), accessFrom(ctx), roleID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setMemberRolesRequest struct {
	RoleIDs []uuid.UUID `json:"role_ids"`
}

// handleSetMemberRoles replaces the set of roles a member holds.
//
// PUT, not PATCH: the body is the complete new set, not a delta. "Add this role"
// and "remove that role" are both expressed by sending the list you want to end
// up with, which makes the operation idempotent and leaves no way to
// accidentally apply a change twice.
func (s *Server) handleSetMemberRoles(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "userID must be a UUID")
		return
	}

	var req setMemberRolesRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	if err := s.identity.SetMemberRoles(ctx, userFrom(ctx), accessFrom(ctx), targetID, req.RoleIDs); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
