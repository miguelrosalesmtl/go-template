package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// API key management, under /organizations/{organization}/api-keys.
//
// These are thin like every other handler. The one rule that matters -- you cannot
// mint a key more powerful than yourself -- lives in the service (checkEscalation),
// so it holds for any caller, not just HTTP ones.

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.identity.ListAPIKeys(r.Context(), organizationFrom(r.Context()).ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

type createAPIKeyRequest struct {
	Name        string                `json:"name"`
	Permissions []identity.Permission `json:"permissions"`
	// ExpiresAt is optional. Omit it for a key that never expires; the service
	// refuses a value in the past.
	ExpiresAt *time.Time `json:"expires_at"`
}

// createAPIKeyResponse carries the plaintext token, which is shown EXACTLY ONCE.
// The server keeps only its hash and cannot reproduce it; a caller that loses it
// must create a new key.
type createAPIKeyResponse struct {
	APIKey identity.APIKey `json:"api_key"`
	Token  string          `json:"token"`
}

// handleCreateAPIKey mints a key and returns its token once.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	ctx := r.Context()
	key, token, err := s.identity.CreateAPIKey(
		ctx, userFrom(ctx), accessFrom(ctx), req.Name, req.Permissions, req.ExpiresAt,
	)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createAPIKeyResponse{APIKey: key, Token: token})
}

// handleRevokeAPIKey kills a key. It takes effect on the key's very next request.
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "keyID must be a UUID")
		return
	}

	ctx := r.Context()
	if err := s.identity.RevokeAPIKey(ctx, userFrom(ctx), accessFrom(ctx), keyID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
