package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// createAPIKey mints a key over HTTP as the given token holder and returns the
// key id and its one-time plaintext token.
func (h *harness) createAPIKey(token, slug, name string, perms []string) (uuid.UUID, string) {
	h.t.Helper()
	rec := h.req(http.MethodPost, "/api/v1/organizations/"+slug+"/api-keys", token,
		map[string]any{"name": name, "permissions": perms})
	mustStatus(h.t, rec, http.StatusCreated)
	var resp struct {
		APIKey struct {
			ID          uuid.UUID `json:"id"`
			TokenPrefix string    `json:"token_prefix"`
		} `json:"api_key"`
		Token string `json:"token"`
	}
	decodeBody(h.t, rec, &resp)
	if resp.Token == "" {
		h.t.Fatal("create api key returned no token")
	}
	return resp.APIKey.ID, resp.Token
}

func TestAPIKeyAuthenticatesAndIsScoped(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// A key that can read members and read the organization, nothing else.
	_, keyToken := h.createAPIKey(ownerToken, "acme", "ci", []string{"members.read", "organization.read"})

	t.Run("the key works on a route within its scope", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme/members", keyToken, nil)
		mustStatus(t, rec, http.StatusOK)
	})

	t.Run("the response flags via_api_key", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme", keyToken, nil)
		mustStatus(t, rec, http.StatusOK)
		var access struct {
			ViaAPIKey bool `json:"via_api_key"`
		}
		decodeBody(t, rec, &access)
		if !access.ViaAPIKey {
			t.Error("a key-authenticated response must set via_api_key")
		}
	})

	t.Run("the key is refused outside its scope", func(t *testing.T) {
		// audit.read is not in the key's scope.
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme/audit", keyToken, nil)
		mustStatus(t, rec, http.StatusForbidden)
		// organization.delete is not either.
		rec = h.req(http.MethodDelete, "/api/v1/organizations/acme", keyToken, nil)
		mustStatus(t, rec, http.StatusForbidden)
	})
}

func TestAPIKeyRejectedOnAccountRoutes(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	_, keyToken := h.createAPIKey(ownerToken, "acme", "ci", []string{"organization.read"})

	// A key is for programmatic access to an organization, not account management.
	// It must not reach /auth/me, /organizations (create), or the /admin surface.
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/organizations"} {
		rec := h.req(http.MethodGet, path, keyToken, nil)
		mustStatus(t, rec, http.StatusForbidden)
	}
}

func TestAPIKeyIsBoundToOneOrganization(t *testing.T) {
	h := newHarness(t)

	ownerA, _ := h.registerAndLogin("a@example.com")
	h.createOrg(ownerA, "acme", "Acme")
	_, keyToken := h.createAPIKey(ownerA, "acme", "ci", []string{"organization.read"})

	ownerB, _ := h.registerAndLogin("b@example.com")
	h.createOrg(ownerB, "globex", "Globex")

	// The acme key used against globex's URL is 404 -- the same answer a stranger
	// gets, so a key cannot even confirm another organization exists.
	rec := h.req(http.MethodGet, "/api/v1/organizations/globex", keyToken, nil)
	mustStatus(t, rec, http.StatusNotFound)
}

func TestAPIKeyRevocationIsImmediate(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	keyID, keyToken := h.createAPIKey(ownerToken, "acme", "ci", []string{"organization.read"})

	// The key works...
	mustStatus(t, h.req(http.MethodGet, "/api/v1/organizations/acme", keyToken, nil), http.StatusOK)

	// ...the owner revokes it...
	mustStatus(t, h.req(http.MethodDelete, "/api/v1/organizations/acme/api-keys/"+keyID.String(), ownerToken, nil),
		http.StatusNoContent)

	// ...and it is dead on the very next request.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/organizations/acme", keyToken, nil), http.StatusUnauthorized)
}

func TestCreateAPIKeyHonoursEscalationOverHTTP(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// An admin holds everything except organization.delete.
	adminToken := h.inviteAndAccept(ownerToken, "acme", "admin", "admin@example.com")

	t.Run("admin cannot mint a key carrying a permission they lack", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/api-keys", adminToken,
			map[string]any{"name": "backdoor", "permissions": []string{"organization.delete"}})
		mustStatus(t, rec, http.StatusForbidden)
	})

	t.Run("admin can mint a key within their own powers", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/api-keys", adminToken,
			map[string]any{"name": "reader", "permissions": []string{"members.read"}})
		mustStatus(t, rec, http.StatusCreated)
	})
}

func TestActionsTakenWithAKeyAreAttributed(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	memberRole := h.roleID(ownerToken, "acme", "member")

	// The key needs invitations.create, plus the member role's own permissions, or
	// the escalation guard on Invite would refuse it.
	_, keyToken := h.createAPIKey(ownerToken, "acme", "inviter",
		[]string{"invitations.create", "organization.read", "members.read"})

	rec := h.req(http.MethodPost, "/api/v1/organizations/acme/invitations", keyToken,
		map[string]any{"email": "invitee@example.com", "role_id": memberRole})
	mustStatus(t, rec, http.StatusCreated)

	// The invitations.created audit entry must carry the api_key_id, so a key's
	// actions are distinguishable from the owner acting in person.
	var tagged int
	err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log
		 WHERE action = 'invitations.created' AND metadata ? 'api_key_id'`).Scan(&tagged)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if tagged == 0 {
		t.Error("an action taken with an API key must be tagged with api_key_id in the audit log")
	}
}
