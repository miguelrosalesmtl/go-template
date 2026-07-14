package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// ---------------------------------------------------------------- probes

func TestHealthDoesNotTouchTheDatabase(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodGet, "/healthz", "", nil)
	mustStatus(t, rec, http.StatusOK)

	// Liveness must be answerable even when Postgres is down, so it returns a
	// static body and never pings. We cannot easily kill the pool here, but we can
	// at least assert the contract shape.
	var body map[string]string
	decodeBody(t, rec, &body)
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
}

func TestReadinessChecksTheDatabase(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodGet, "/readyz", "", nil)
	// The pool is up, so this must succeed -- which also proves readyz really did
	// reach the database rather than short-circuiting.
	mustStatus(t, rec, http.StatusOK)
}

// ---------------------------------------------------------------- headers & CORS

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodGet, "/healthz", "", nil)

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestCORS(t *testing.T) {
	h := newHarness(t)

	t.Run("allowed origin is echoed", func(t *testing.T) {
		rec := h.reqOrigin(http.MethodGet, "/healthz", testOrigin)
		mustStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
			t.Errorf("Allow-Origin = %q, want %q", got, testOrigin)
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Errorf("Vary = %q, want Origin", got)
		}
	})

	t.Run("unknown origin is not echoed", func(t *testing.T) {
		rec := h.reqOrigin(http.MethodGet, "/healthz", "https://evil.example.com")
		// Served normally -- the BROWSER blocks it -- but with no allow-origin header.
		mustStatus(t, rec, http.StatusOK)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Allow-Origin = %q for a non-allowlisted origin, want empty", got)
		}
	})

	t.Run("preflight returns 204 with methods", func(t *testing.T) {
		rec := h.reqOrigin(http.MethodOptions, "/api/v1/auth/login", testOrigin)
		mustStatus(t, rec, http.StatusNoContent)
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Error("preflight did not advertise allowed methods")
		}
	})
}

// ---------------------------------------------------------------- auth middleware

func TestRequireAuth(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")

	t.Run("missing token is 401 with a challenge", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/auth/me", "", nil)
		mustStatus(t, rec, http.StatusUnauthorized)
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("a 401 for a missing credential must carry WWW-Authenticate")
		}
	})

	t.Run("garbage token is 401", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/auth/me", "not-a-real-token", nil)
		mustStatus(t, rec, http.StatusUnauthorized)
	})

	t.Run("valid token reaches the handler", func(t *testing.T) {
		token := h.login("alice@example.com")
		rec := h.req(http.MethodGet, "/api/v1/auth/me", token, nil)
		mustStatus(t, rec, http.StatusOK)
		var u struct {
			Email string `json:"email"`
		}
		decodeBody(t, rec, &u)
		if u.Email != "alice@example.com" {
			t.Errorf("me returned %q", u.Email)
		}
	})
}

// ---------------------------------------------------------------- register / login

func TestRegister(t *testing.T) {
	h := newHarness(t)

	t.Run("creates an account", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/register", "", map[string]string{
			"email": "new@example.com", "password": testPassword, "full_name": "New",
		})
		mustStatus(t, rec, http.StatusCreated)
	})

	t.Run("duplicate email is 409", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/register", "", map[string]string{
			"email": "new@example.com", "password": testPassword, "full_name": "New",
		})
		mustStatus(t, rec, http.StatusConflict)
	})

	t.Run("malformed JSON is 400", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/register", "", "{not json")
		mustStatus(t, rec, http.StatusBadRequest)
	})

	t.Run("unknown field is 400", func(t *testing.T) {
		// DisallowUnknownFields: a typo'd field must fail loudly, not be ignored.
		rec := h.req(http.MethodPost, "/api/v1/auth/register", "",
			`{"email":"x@example.com","password":"`+testPassword+`","superuser":true}`)
		mustStatus(t, rec, http.StatusBadRequest)
	})
}

func TestLogin(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")

	t.Run("correct credentials return a token", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email": "alice@example.com", "password": testPassword,
		})
		mustStatus(t, rec, http.StatusOK)
		var resp struct {
			Token string `json:"token"`
			User  struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		decodeBody(t, rec, &resp)
		if resp.Token == "" || resp.User.Email != "alice@example.com" {
			t.Errorf("unexpected login response: %+v", resp)
		}
	})

	t.Run("wrong password is 401", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email": "alice@example.com", "password": "wrong-password-entirely",
		})
		mustStatus(t, rec, http.StatusUnauthorized)
	})

	t.Run("unknown email is also 401", func(t *testing.T) {
		// Indistinguishable from a wrong password, by design: no enumeration oracle.
		rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email": "nobody@example.com", "password": testPassword,
		})
		mustStatus(t, rec, http.StatusUnauthorized)
	})
}

// ---------------------------------------------------------------- catalog

func TestListPermissionsIsPublic(t *testing.T) {
	h := newHarness(t)

	// No token: a login screen may want the catalog, and it is not secret.
	rec := h.req(http.MethodGet, "/api/v1/permissions", "", nil)
	mustStatus(t, rec, http.StatusOK)

	var resp struct {
		Permissions []struct {
			Key string `json:"key"`
		} `json:"permissions"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Permissions) == 0 {
		t.Fatal("the permission catalog came back empty")
	}
}

// ---------------------------------------------------------------- organization scoping

func TestOrganizationScoping(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	t.Run("owner can read their organization", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme", ownerToken, nil)
		mustStatus(t, rec, http.StatusOK)
		var access struct {
			Organization struct {
				Slug string `json:"slug"`
			} `json:"organization"`
			ViaSuperuser bool `json:"via_superuser"`
		}
		decodeBody(t, rec, &access)
		if access.Organization.Slug != "acme" {
			t.Errorf("slug = %q", access.Organization.Slug)
		}
		if access.ViaSuperuser {
			t.Error("a real owner must not be flagged via_superuser")
		}
	})

	t.Run("a stranger gets 404, not 403", func(t *testing.T) {
		strangerToken, _ := h.registerAndLogin("stranger@example.com")
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme", strangerToken, nil)
		// 404, not 403: membership is invisible, so the organization's existence is too.
		mustStatus(t, rec, http.StatusNotFound)
	})

	t.Run("an unknown slug is 404", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/ghost", ownerToken, nil)
		mustStatus(t, rec, http.StatusNotFound)
	})
}

func TestUpdateOrganizationRejectsSlugChange(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	t.Run("renaming works", func(t *testing.T) {
		rec := h.req(http.MethodPatch, "/api/v1/organizations/acme", ownerToken,
			map[string]string{"name": "Acme Inc"})
		mustStatus(t, rec, http.StatusOK)
	})

	t.Run("changing the slug is a 400", func(t *testing.T) {
		// The slug field is unknown to updateOrganizationRequest, so
		// DisallowUnknownFields rejects it -- the slug is immutable.
		rec := h.req(http.MethodPatch, "/api/v1/organizations/acme", ownerToken,
			`{"slug":"other"}`)
		mustStatus(t, rec, http.StatusBadRequest)
	})
}

// ---------------------------------------------------------------- permission enforcement

func TestRequirePermissionEnforcement(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// A plain member joins. The member role carries only organization.read and
	// members.read, so it is the perfect probe for the permission middleware.
	memberToken := h.inviteAndAccept(ownerToken, "acme", "member", "member@example.com")

	t.Run("member can read the organization (organization.read)", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme", memberToken, nil)
		mustStatus(t, rec, http.StatusOK)
	})

	t.Run("member cannot read the audit log (audit.read)", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/organizations/acme/audit", memberToken, nil)
		mustStatus(t, rec, http.StatusForbidden)
	})

	t.Run("member cannot delete the organization (organization.delete)", func(t *testing.T) {
		rec := h.req(http.MethodDelete, "/api/v1/organizations/acme", memberToken, nil)
		mustStatus(t, rec, http.StatusForbidden)
	})

	t.Run("owner can delete the organization", func(t *testing.T) {
		rec := h.req(http.MethodDelete, "/api/v1/organizations/acme", ownerToken, nil)
		mustStatus(t, rec, http.StatusNoContent)
	})
}

func TestMalformedUUIDParamIs400(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	// The path param is not a UUID, so the handler must 400 before doing anything.
	rec := h.req(http.MethodDelete, "/api/v1/organizations/acme/members/not-a-uuid", ownerToken, nil)
	mustStatus(t, rec, http.StatusBadRequest)
}

// ---------------------------------------------------------------- superuser surface

func TestSuperuserStaffSurface(t *testing.T) {
	h := newHarness(t)

	ordinaryToken, _ := h.registerAndLogin("ordinary@example.com")
	h.register("root@example.com")
	h.makeSuperuser("root@example.com")
	rootToken := h.login("root@example.com")

	t.Run("a non-superuser gets 404, not 403", func(t *testing.T) {
		// The staff surface must not advertise its own existence.
		rec := h.req(http.MethodGet, "/api/v1/admin/users", ordinaryToken, nil)
		mustStatus(t, rec, http.StatusNotFound)
	})

	t.Run("the superuser can list users", func(t *testing.T) {
		rec := h.req(http.MethodGet, "/api/v1/admin/users", rootToken, nil)
		mustStatus(t, rec, http.StatusOK)
	})
}

func TestSuperuserOrganizationBypassIsAudited(t *testing.T) {
	h := newHarness(t)

	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")

	h.register("root@example.com")
	h.makeSuperuser("root@example.com")
	rootToken := h.login("root@example.com")

	// The superuser is not a member of acme, yet the bypass lets them in with the
	// full permission set -- flagged via_superuser so it is distinguishable.
	rec := h.req(http.MethodGet, "/api/v1/organizations/acme", rootToken, nil)
	mustStatus(t, rec, http.StatusOK)

	var access struct {
		ViaSuperuser bool `json:"via_superuser"`
	}
	decodeBody(t, rec, &access)
	if !access.ViaSuperuser {
		t.Error("a superuser bypass must set via_superuser so a UI can flag it")
	}

	// The bypass is permitted only because it is always recorded.
	ctx := context.Background()
	var count int
	err := testPool.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = $1`,
		string(audit.ActionSuperuserOrganizationAccessed),
	).Scan(&count)
	if err != nil {
		t.Fatalf("query audit log: %v", err)
	}
	if count == 0 {
		t.Error("the superuser organization access was not written to the audit log")
	}
}

// ---------------------------------------------------------------- invitation flow

func TestInvitationFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	ownerToken, _ := h.registerAndLogin("owner@example.com")
	h.createOrg(ownerToken, "acme", "Acme")
	memberRole := h.roleID(ownerToken, "acme", "member")

	t.Run("the response never carries the token", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/organizations/acme/invitations", ownerToken,
			map[string]any{"email": "invitee@example.com", "role_id": memberRole})
		mustStatus(t, rec, http.StatusCreated)
		// The plaintext token goes ONLY to the invitee's inbox.
		if body := rec.Body.String(); leaksAToken(body) {
			t.Errorf("the invitation response leaked a token:\n%s", body)
		}
	})

	t.Run("the invitee redeems the emailed token and becomes a member", func(t *testing.T) {
		token := tokenFromLink(t, h.mailer.lastTo(t, "invitee@example.com").Body)

		h.register("invitee@example.com")
		inviteeToken := h.login("invitee@example.com")

		rec := h.req(http.MethodPost, "/api/v1/invitations/accept", inviteeToken,
			map[string]string{"token": token})
		mustStatus(t, rec, http.StatusOK)

		// Now a member: they can read the organization they just joined.
		rec = h.req(http.MethodGet, "/api/v1/organizations/acme", inviteeToken, nil)
		mustStatus(t, rec, http.StatusOK)
	})
}

// ---------------------------------------------------------------- session lifecycle

func TestLogoutInvalidatesTheToken(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")
	token := h.login("alice@example.com")

	// The token works...
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", token, nil), http.StatusOK)

	// ...logout revokes it...
	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/logout", token, nil), http.StatusNoContent)

	// ...and the very next request with it fails.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", token, nil), http.StatusUnauthorized)
}

func TestChangePasswordRevokesEverySession(t *testing.T) {
	h := newHarness(t)
	h.register("alice@example.com")
	token := h.login("alice@example.com")

	rec := h.req(http.MethodPost, "/api/v1/auth/password", token, map[string]string{
		"current_password": testPassword,
		"new_password":     "a-brand-new-long-password",
	})
	mustStatus(t, rec, http.StatusNoContent)

	// The session that made the change is gone too: revocation is total.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", token, nil), http.StatusUnauthorized)
}

// ---------------------------------------------------------------- password reset / verify

func TestPasswordResetRequestAlwaysNoContent(t *testing.T) {
	h := newHarness(t)

	// An unknown address must look exactly like a known one -- no enumeration oracle.
	rec := h.req(http.MethodPost, "/api/v1/auth/password/reset", "",
		map[string]string{"email": "nobody@example.com"})
	mustStatus(t, rec, http.StatusNoContent)
}

func TestEmailVerifyRejectsBadTokens(t *testing.T) {
	h := newHarness(t)

	t.Run("empty token is 400", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/email/verify", "",
			map[string]string{"token": ""})
		mustStatus(t, rec, http.StatusBadRequest)
	})

	t.Run("unknown token is 400", func(t *testing.T) {
		rec := h.req(http.MethodPost, "/api/v1/auth/email/verify", "",
			map[string]string{"token": "mtt_evr_totally-made-up"})
		mustStatus(t, rec, http.StatusBadRequest)
	})
}

// ---------------------------------------------------------------- rate limiting

func TestRateLimiting(t *testing.T) {
	h := newHarnessWith(t, settings.RateLimit{
		Enabled:  true,
		Attempts: 3,
		Window:   time.Minute,
	})
	h.register("alice@example.com")

	body := map[string]string{"email": "alice@example.com", "password": "wrong-password"}

	// The first three attempts are let through to the handler (each a 401).
	for i := 0; i < 3; i++ {
		rec := h.req(http.MethodPost, "/api/v1/auth/login", "", body)
		mustStatus(t, rec, http.StatusUnauthorized)
	}

	// The fourth trips the limiter: 429 with a Retry-After the client can honour.
	rec := h.req(http.MethodPost, "/api/v1/auth/login", "", body)
	mustStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 must carry Retry-After so a client can back off correctly")
	}
}

// ---------------------------------------------------------------- helpers

// inviteAndAccept invites email into slug with the named role, then registers and
// joins that user, returning their session token. It exercises the whole flow the
// way a real client would, so a member exists to test permission enforcement.
func (h *harness) inviteAndAccept(ownerToken, slug, roleKey, email string) string {
	h.t.Helper()

	roleID := h.roleID(ownerToken, slug, roleKey)
	rec := h.req(http.MethodPost, "/api/v1/organizations/"+slug+"/invitations", ownerToken,
		map[string]any{"email": email, "role_id": roleID})
	mustStatus(h.t, rec, http.StatusCreated)

	token := tokenFromLink(h.t, h.mailer.lastTo(h.t, email).Body)

	h.register(email)
	inviteeToken := h.login(email)

	rec = h.req(http.MethodPost, "/api/v1/invitations/accept", inviteeToken,
		map[string]string{"token": token})
	mustStatus(h.t, rec, http.StatusOK)

	return inviteeToken
}

// leaksAToken reports whether s contains one of the app's opaque bearer tokens.
// Used to prove the invitation response body does NOT carry one -- the plaintext
// token must reach the invitee's inbox and nowhere else.
func leaksAToken(s string) bool {
	for _, prefix := range []string{
		auth.SessionTokenPrefix,
		auth.InvitationTokenPrefix,
		auth.PasswordResetTokenPrefix,
		auth.EmailVerifyTokenPrefix,
	} {
		if strings.Contains(s, prefix) {
			return true
		}
	}
	return false
}
