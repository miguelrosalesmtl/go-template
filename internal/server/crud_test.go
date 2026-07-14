package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// These cover the CRUD and listing handlers, the role-management endpoints (where
// the escalation guard shows up at the HTTP layer), the superuser admin surface,
// and the two token-spending flows that need a real emailed token.

// ---------------------------------------------------------------- sessions

func TestListAndRevokeSessions(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")

	first := h.login("alice@example.com")
	second := h.login("alice@example.com") // a second device

	// List shows both, and flags exactly the one making the request.
	rec := h.req(http.MethodGet, "/api/v1/auth/sessions", first, nil)
	mustStatus(t, rec, http.StatusOK)
	var listed struct {
		Sessions []struct {
			ID      uuid.UUID `json:"id"`
			Current bool      `json:"current"`
		} `json:"sessions"`
	}
	decodeBody(t, rec, &listed)
	if len(listed.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(listed.Sessions))
	}

	// Find the OTHER session (the second login) and revoke it from the first.
	var other uuid.UUID
	for _, s := range listed.Sessions {
		if !s.Current {
			other = s.ID
		}
	}
	rec = h.req(http.MethodDelete, "/api/v1/auth/sessions/"+other.String(), first, nil)
	mustStatus(t, rec, http.StatusNoContent)

	// The revoked device is signed out; the one that did the revoking still works.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", second, nil), http.StatusUnauthorized)
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", first, nil), http.StatusOK)
}

// ---------------------------------------------------------------- listing

func TestOrganizationAndMemberListing(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	t.Run("my organizations lists the one I own", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations", ownerToken, nil)
		mustStatus(t, rec, http.StatusOK)
		var resp struct {
			Organizations []struct {
				Organization struct {
					Slug string `json:"slug"`
				} `json:"organization"`
			} `json:"organizations"`
		}
		decodeBody(t, rec, &resp)
		if len(resp.Organizations) != 1 || resp.Organizations[0].Organization.Slug != "acme" {
			t.Fatalf("unexpected organization list: %+v", resp.Organizations)
		}
	})

	t.Run("members starts at one and grows on join", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme/members", ownerToken, nil)
		mustStatus(t, rec, http.StatusOK)
		var before struct {
			Members []json0 `json:"members"`
		}
		decodeBody(t, rec, &before)
		if len(before.Members) != 1 {
			t.Fatalf("expected 1 member (the owner), got %d", len(before.Members))
		}

		h.inviteAndAccept(ownerToken, "acme", "member", "member@example.com")

		rec = h.req(http.MethodGet, "/api/v1/organizations/acme/members", ownerToken, nil)
		mustStatus(t, rec, http.StatusOK)
		var after struct {
			Members []json0 `json:"members"`
		}
		decodeBody(t, rec, &after)
		if len(after.Members) != 2 {
			t.Fatalf("expected 2 members after a join, got %d", len(after.Members))
		}
	})
}

func TestInvitationListingAndRevoke(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	memberRole := h.roleID(ownerToken, "acme", "member")

	rec := h.req(http.MethodPost, "/api/v1/organizations/acme/invitations", ownerToken,
		map[string]any{"email": "invitee@example.com", "role_id": memberRole})
	mustStatus(t, rec, http.StatusCreated)
	var inv struct {
		ID uuid.UUID `json:"id"`
	}
	decodeBody(t, rec, &inv)

	rec = h.req(http.MethodGet, "/api/v1/organizations/acme/invitations", ownerToken, nil)
	mustStatus(t, rec, http.StatusOK)
	var listed struct {
		Invitations []json0 `json:"invitations"`
	}
	decodeBody(t, rec, &listed)
	if len(listed.Invitations) != 1 {
		t.Fatalf("expected 1 pending invitation, got %d", len(listed.Invitations))
	}

	rec = h.req(http.MethodDelete, "/api/v1/organizations/acme/invitations/"+inv.ID.String(), ownerToken, nil)
	mustStatus(t, rec, http.StatusNoContent)
}

func TestAuditLogListing(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// Creating the organization already wrote audit entries, so the owner (who holds
	// audit.read) sees a non-empty log.
	rec := h.req(http.MethodGet, "/api/v1/organizations/acme/audit", ownerToken, nil)
	mustStatus(t, rec, http.StatusOK)
	var resp struct {
		Entries []json0 `json:"entries"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Entries) == 0 {
		t.Error("the audit log should already hold the organization-created entry")
	}

	// A malformed cursor is a 400, not a 500.
	rec = h.req(http.MethodGet, "/api/v1/organizations/acme/audit?before=not-a-uuid", ownerToken, nil)
	mustStatus(t, rec, http.StatusBadRequest)
}

// ---------------------------------------------------------------- roles

func TestRoleManagementOverHTTP(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	var roleID uuid.UUID

	t.Run("create a custom role", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/roles", ownerToken, map[string]any{
			"key":         "auditor",
			"name":        "Auditor",
			"permissions": []string{"audit.read", "organization.read"},
		})
		mustStatus(t, rec, http.StatusCreated)
		var role struct {
			ID uuid.UUID `json:"id"`
		}
		decodeBody(t, rec, &role)
		roleID = role.ID
	})

	t.Run("update it", func(t *testing.T) {
		rec := h.req(http.MethodPut, "/api/v1/organizations/acme/roles/"+roleID.String(), ownerToken,
			map[string]any{"name": "Read-only Auditor", "permissions": []string{"audit.read"}})
		mustStatus(t, rec, http.StatusOK)
	})

	t.Run("delete it", func(t *testing.T) {
		rec := h.req(http.MethodDelete, "/api/v1/organizations/acme/roles/"+roleID.String(), ownerToken, nil)
		mustStatus(t, rec, http.StatusNoContent)
	})
}

func TestRoleCreationHonoursTheEscalationGuard(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// An admin holds everything EXCEPT organization.delete.
	adminToken := h.inviteAndAccept(ownerToken, "acme", "admin", "admin@example.com")

	t.Run("admin cannot mint a role carrying a permission they lack", func(t *testing.T) {
		// organization.delete would let them escalate straight past every limit on them.
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/roles", adminToken, map[string]any{
			"key":         "backdoor",
			"name":        "Backdoor",
			"permissions": []string{"organization.delete"},
		})
		// 403, and the escalation is recorded (checked below).
		mustStatus(t, rec, http.StatusForbidden)
	})

	t.Run("admin can mint a role from permissions they do hold", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/roles", adminToken, map[string]any{
			"key":         "greeter",
			"name":        "Greeter",
			"permissions": []string{"members.read"},
		})
		mustStatus(t, rec, http.StatusCreated)
	})

	// The refused escalation left a trail.
	var count int
	err := testPool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE action = 'access.escalation_denied'`).Scan(&count)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if count == 0 {
		t.Error("a denied escalation must be audited")
	}
}

func TestSetMemberRoles(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	memberID := mustUserID(t, h.inviteAndAccept(ownerToken, "acme", "member", "member@example.com"), h)

	adminRole := h.roleID(ownerToken, "acme", "admin")
	memberRole := h.roleID(ownerToken, "acme", "member")

	// PUT the COMPLETE new set: promote the member to also hold admin.
	rec := h.req(http.MethodPut,
		"/api/v1/organizations/acme/members/"+memberID.String()+"/roles", ownerToken,
		map[string]any{"role_ids": []uuid.UUID{memberRole, adminRole}})
	mustStatus(t, rec, http.StatusNoContent)
}

// ---------------------------------------------------------------- leaving

func TestLeaveOrganization(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	t.Run("a member may walk out", func(t *testing.T) {
		memberToken := h.inviteAndAccept(ownerToken, "acme", "member", "member@example.com")
		rec := h.req(http.MethodDelete, "/api/v1/organizations/acme/members/me", memberToken, nil)
		mustStatus(t, rec, http.StatusNoContent)
	})

	t.Run("the sole owner cannot", func(t *testing.T) {
		// The last-owner rule: leaving would strand the organization with no owner.
		rec := h.req(http.MethodDelete, "/api/v1/organizations/acme/members/me", ownerToken, nil)
		mustStatus(t, rec, http.StatusConflict)
	})
}

// ---------------------------------------------------------------- admin surface

func TestAdminListingDeactivationAndRestore(t *testing.T) {
	h := newHarness(t)

	ownerToken, _ := h.registerAndLogin("owner@example.com")
	org := h.createOrg(ownerToken, "acme", "Acme")

	victimToken, victimID := h.registerAndLogin("victim@example.com")

	h.register("root@example.com")
	h.makeSuperuser("root@example.com")
	rootToken := h.login("root@example.com")

	t.Run("superuser lists all organizations", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/admin/organizations", rootToken, nil)
		mustStatus(t, rec, http.StatusOK)
	})

	t.Run("deactivating a user locks them out on the next request", func(t *testing.T) {
		rec := h.req(http.MethodPatch, "/api/v1/admin/users/"+victimID.String(), rootToken,
			map[string]bool{"is_active": false})
		mustStatus(t, rec, http.StatusOK)

		// Deactivation revokes sessions in the same transaction.
		mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", victimToken, nil), http.StatusUnauthorized)
	})

	t.Run("a soft-deleted organization can be restored", func(t *testing.T) {
		mustStatus(t, h.req(http.MethodDelete, "/api/v1/organizations/acme", ownerToken, nil), http.StatusNoContent)

		// The owner can no longer see it -- which is why restore is a superuser job.
		mustStatus(t, h.req(http.MethodGet, "/api/v1/organizations/acme", ownerToken, nil), http.StatusNotFound)

		rec := h.req(http.MethodPost, "/api/v1/admin/organizations/"+org.ID.String()+"/restore", rootToken,
			map[string]string{})
		mustStatus(t, rec, http.StatusOK)

		// And it is back for its owner.
		mustStatus(t, h.req(http.MethodGet, "/api/v1/organizations/acme", ownerToken, nil), http.StatusOK)
	})
}

// ---------------------------------------------------------------- token-spending flows

func TestPasswordResetHappyPath(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")
	oldToken := h.login("alice@example.com")

	// Request the reset, then read the emailed token as the user would.
	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/password/reset", "",
		map[string]string{"email": "alice@example.com"}), http.StatusNoContent)
	token := tokenFromLink(t, h.mailer.lastTo(t, "alice@example.com").Body)

	const newPassword = "an-entirely-new-password"
	rec := h.req(http.MethodPost, "/api/v1/auth/password/reset/confirm", "",
		map[string]string{"token": token, "new_password": newPassword})
	mustStatus(t, rec, http.StatusNoContent)

	// The old session is dead, the old password no longer works, the new one does.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", oldToken, nil), http.StatusUnauthorized)
	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": "alice@example.com", "password": testPassword}), http.StatusUnauthorized)
	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": "alice@example.com", "password": newPassword}), http.StatusOK)
}

func TestResendAndVerifyEmail(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")
	token := h.login("alice@example.com")

	// Resend goes to the caller's own address only -- no parameter for anyone else's.
	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/email/verify/resend", token, nil), http.StatusNoContent)

	verifyToken := tokenFromLink(t, h.mailer.lastTo(t, "alice@example.com").Body)
	rec := h.req(http.MethodPost, "/api/v1/auth/email/verify", "",
		map[string]string{"token": verifyToken})
	mustStatus(t, rec, http.StatusOK)

	var user struct {
		EmailVerifiedAt *string `json:"email_verified_at"`
	}
	decodeBody(t, rec, &user)
	if user.EmailVerifiedAt == nil {
		t.Error("email_verified_at should be set after a successful verification")
	}
}

// ---------------------------------------------------------------- helpers

// json0 is a throwaway target for list responses whose element shape does not
// matter to a test -- only the count does.
type json0 = map[string]any

// mustUserID resolves the id of the user a token belongs to, via /auth/me. It lets
// a test recover the id when it only holds a token (inviteAndAccept returns one).
func mustUserID(t *testing.T, token string, h *harness) uuid.UUID {
	t.Helper()
	rec := h.req(http.MethodGet, "/api/v1/auth/me", token, nil)
	mustStatus(t, rec, http.StatusOK)
	var u struct {
		ID uuid.UUID `json:"id"`
	}
	decodeBody(t, rec, &u)
	return u.ID
}
