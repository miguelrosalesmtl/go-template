package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// API keys: programmatic, organization-scoped credentials.
//
// A key is the machine counterpart of a session. Where a session belongs to a
// person and derives its power from that person's roles, a key belongs to an
// organization and carries a FROZEN set of permissions chosen when it is minted.
// The two are deliberately parallel: both are opaque bearer tokens, shown once,
// stored only as a SHA-256 hash.
//
// The one rule that makes keys safe is the same one that governs roles: you cannot
// mint a key more powerful than yourself. checkEscalation enforces it, so an admin
// cannot create a key that can delete the organization they themselves cannot.

// apiKeyDisplayPrefixLen is how much of the plaintext token is kept, in the clear,
// as an identifier. Enough to tell two keys apart in a list; far too little to
// guess the rest of a 256-bit secret.
const apiKeyDisplayPrefixLen = len(auth.APIKeyTokenPrefix) + 4

// CreateAPIKey mints a key for the organization and returns it together with its
// plaintext token. THE PLAINTEXT IS RETURNED EXACTLY ONCE, here; it is never
// stored and cannot be shown again. The caller (the HTTP handler) passes it to the
// user, who copies it into their automation.
//
// The caller must hold every permission they are putting into the key -- the same
// escalation guard as creating a role. Without it, apikeys.create would be a
// long-winded way to spell "owner".
func (s *Service) CreateAPIKey(
	ctx context.Context,
	actor User,
	access OrganizationAccess,
	name string,
	perms []Permission,
	expiresAt *time.Time,
) (APIKey, string, error) {
	name, set, err := validateAPIKeyInput(name, perms, expiresAt)
	if err != nil {
		return APIKey{}, "", err
	}
	if err := checkEscalation(access, set); err != nil {
		return APIKey{}, "", err
	}

	plaintext, digest, err := auth.NewToken(auth.APIKeyTokenPrefix)
	if err != nil {
		return APIKey{}, "", err
	}
	displayPrefix := plaintext[:apiKeyDisplayPrefixLen]

	var key APIKey
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		key, err = repo.CreateAPIKey(ctx, access.Organization.ID, name, displayPrefix, digest, actor.ID, set, expiresAt)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionAPIKeyCreated,
			TargetType:     "api_key",
			TargetID:       key.ID.String(),
			Metadata: map[string]any{
				"name":        name,
				"permissions": set.Slice(),
			},
		})
	})
	if err != nil {
		return APIKey{}, "", err
	}
	return key, plaintext, nil
}

// ListAPIKeys returns the organization's live keys. It never carries a token: the
// plaintext was shown once and only its hash was ever stored.
func (s *Service) ListAPIKeys(ctx context.Context, organizationID uuid.UUID) ([]APIKey, error) {
	return s.repo.ListAPIKeys(ctx, organizationID)
}

// RevokeAPIKey kills a key. It takes effect on the key's very next request, since
// authentication checks revoked_at every time -- the same immediate revocation the
// sessions model gives a human.
func (s *Service) RevokeAPIKey(ctx context.Context, actor User, access OrganizationAccess, keyID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		key, err := repo.RevokeAPIKey(ctx, access.Organization.ID, keyID)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionAPIKeyRevoked,
			TargetType:     "api_key",
			TargetID:       key.ID.String(),
			Metadata:       map[string]any{"name": key.Name},
		})
	})
}

// AuthenticateAPIKey resolves a plaintext key token into everything the middleware
// needs to serve the request: the key's organization, its permission scope, and
// the user it acts as (its creator). It is the key-authentication counterpart of
// Authenticate for sessions.
//
// The organization and the acting user are loaded fresh, so a key cannot outlive a
// soft-deleted organization or a deactivated creator -- the repository query
// already refuses those, and these loads then succeed by construction.
func (s *Service) AuthenticateAPIKey(ctx context.Context, token string) (APIKey, Organization, User, error) {
	if token == "" {
		return APIKey{}, Organization{}, User{}, ErrUnauthenticated
	}

	key, err := s.repo.AuthenticateAPIKey(ctx, auth.HashToken(token))
	if err != nil {
		return APIKey{}, Organization{}, User{}, err
	}

	org, err := s.repo.GetOrganizationByID(ctx, key.OrganizationID)
	if err != nil {
		return APIKey{}, Organization{}, User{}, err
	}

	actor, err := s.repo.GetUserByID(ctx, key.CreatedBy)
	if err != nil {
		return APIKey{}, Organization{}, User{}, err
	}

	return key, org, actor, nil
}

// validateAPIKeyInput checks the fields a caller controls when minting a key.
func validateAPIKeyInput(name string, perms []Permission, expiresAt *time.Time) (string, PermissionSet, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", nil, invalid("api key name is required")
	case len(name) > 100:
		return "", nil, invalid("api key name must be at most 100 characters")
	case len(perms) == 0:
		return "", nil, invalid("an api key must grant at least one permission")
	}

	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return "", nil, invalid("api key expiry must be in the future")
	}

	set := PermissionSet{}
	for _, p := range perms {
		if !p.Valid() {
			return "", nil, invalid(fmt.Sprintf("%q is not a permission this application enforces", p))
		}
		set[p] = struct{}{}
	}
	return name, set, nil
}
