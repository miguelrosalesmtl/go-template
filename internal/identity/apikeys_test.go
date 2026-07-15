package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/auth"
)

func TestCreateAPIKeyEnforcesEscalation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	acme, owner := setupOrganizationWithOwner(t, svc)
	ownerAccess := accessFor(t, svc, owner, acme.Slug)

	// The owner holds everything, so any scope is permitted.
	if _, _, err := svc.CreateAPIKey(ctx, owner, ownerAccess, "deploy",
		[]Permission{PermOrganizationDelete, PermMembersRead}, nil); err != nil {
		t.Fatalf("owner should mint a key with any scope: %v", err)
	}

	// An admin does not hold organization.delete, so a key carrying it is exactly
	// the escalation the guard exists to stop -- otherwise apikeys.create would be a
	// long way to spell "owner".
	admin := joinOrganization(t, svc, owner, acme, "admin@example.com", RoleKeyAdmin)
	adminAccess := accessFor(t, svc, admin, acme.Slug)

	if _, _, err := svc.CreateAPIKey(ctx, admin, adminAccess, "sneaky",
		[]Permission{PermOrganizationDelete}, nil); !errors.Is(err, ErrEscalation) {
		t.Fatalf("admin minting a key with organization.delete: got %v, want ErrEscalation", err)
	}

	// A scope within their own powers is fine.
	if _, _, err := svc.CreateAPIKey(ctx, admin, adminAccess, "ok",
		[]Permission{PermMembersRead}, nil); err != nil {
		t.Fatalf("admin should mint a key from permissions they hold: %v", err)
	}
}

func TestAuthenticateAPIKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	acme, owner := setupOrganizationWithOwner(t, svc)
	access := accessFor(t, svc, owner, acme.Slug)

	_, token, err := svc.CreateAPIKey(ctx, owner, access, "ci", []Permission{PermMembersRead}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	key, org, actor, err := svc.AuthenticateAPIKey(ctx, token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if org.ID != acme.ID {
		t.Errorf("resolved organization = %s, want acme", org.Slug)
	}
	if actor.ID != owner.ID {
		t.Errorf("acting user = %s, want the creator", actor.Email)
	}
	if !key.Permissions.Has(PermMembersRead) {
		t.Error("the key's scope lost members.read")
	}
	if key.Permissions.Has(PermOrganizationDelete) {
		t.Error("the key's scope gained a permission it was never granted")
	}

	// A token that matches nothing is unauthenticated, never a 500.
	if _, _, _, err := svc.AuthenticateAPIKey(ctx, "mtt_key_not-a-real-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("bad token = %v, want ErrUnauthenticated", err)
	}
}

func TestAPIKeyDiesWithItsCreator(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	acme, owner := setupOrganizationWithOwner(t, svc)
	access := accessFor(t, svc, owner, acme.Slug)

	_, token, err := svc.CreateAPIKey(ctx, owner, access, "ci", []Permission{PermMembersRead}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Works while the creator is active.
	if _, _, _, err := svc.AuthenticateAPIKey(ctx, token); err != nil {
		t.Fatalf("key should work while its creator is active: %v", err)
	}

	// Deactivating the creator disables the key on its very next use -- offboarding
	// a person also disables their automation.
	root := makeSuperuser(t, svc, "root@example.com")
	if _, err := svc.SetUserActive(ctx, root, owner.ID, false); err != nil {
		t.Fatalf("deactivate creator: %v", err)
	}
	if _, _, _, err := svc.AuthenticateAPIKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a key must die with its deactivated creator, got %v", err)
	}
}

func TestExpiredAPIKeyIsRejected(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	acme, owner := setupOrganizationWithOwner(t, svc)

	// The service refuses a past expiry at creation, so insert an already-expired
	// key through the repository to exercise the authentication query's expiry check.
	plaintext, digest, err := auth.NewToken(auth.APIKeyTokenPrefix)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := NewRepository(svc.pool).CreateAPIKey(
		ctx, acme.ID, "old", plaintext[:apiKeyDisplayPrefixLen], digest, owner.ID,
		NewPermissionSet(PermMembersRead), &past,
	); err != nil {
		t.Fatalf("insert expired key: %v", err)
	}

	if _, _, _, err := svc.AuthenticateAPIKey(ctx, plaintext); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("an expired key must be rejected, got %v", err)
	}
}

func TestRevokedAPIKeyIsRejected(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	acme, owner := setupOrganizationWithOwner(t, svc)
	access := accessFor(t, svc, owner, acme.Slug)

	key, token, err := svc.CreateAPIKey(ctx, owner, access, "ci", []Permission{PermMembersRead}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, _, err := svc.AuthenticateAPIKey(ctx, token); err != nil {
		t.Fatalf("key should work before revocation: %v", err)
	}

	if err := svc.RevokeAPIKey(ctx, owner, access, key.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, _, err := svc.AuthenticateAPIKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("a revoked key must be rejected, got %v", err)
	}
}
