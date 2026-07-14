package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	netmail "net/mail" // aliased: internal/mail is also imported, for sending
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// Service holds the identity business rules: what must be validated, what must
// happen atomically, and what must be audited. HTTP handlers call it and do
// nothing else of consequence, so the same rules would apply to a gRPC or CLI
// front end.
type Service struct {
	pool    *pgxpool.Pool
	repo    *Repository // pool-backed, for single-statement operations
	hasher  *auth.Hasher
	mailer  mail.Mailer
	cfg     settings.Auth
	mailCfg settings.Mail
	log     *slog.Logger
}

// NewService builds the identity service.
//
// The mailer is a dependency rather than something the service constructs,
// because the two flows that need it -- invitations and password resets -- are the
// two places where getting it wrong is a security bug, and a test must be able to
// see exactly what was sent.
func NewService(
	pool *pgxpool.Pool,
	cfg settings.Auth,
	mailCfg settings.Mail,
	mailer mail.Mailer,
	log *slog.Logger,
) *Service {
	return &Service{
		pool:    pool,
		repo:    NewRepository(pool),
		hasher:  auth.NewHasher(cfg.ArgonMemoryKiB, cfg.ArgonIterations, cfg.ArgonParallelism),
		mailer:  mailer,
		cfg:     cfg,
		mailCfg: mailCfg,
		log:     log,
	}
}

// RequestMeta is the ambient information about an HTTP request that the service
// records on sessions and audit entries.
type RequestMeta struct {
	UserAgent string
	IPAddress string
}

// ---------------------------------------------------------------- registration

// Register creates a global user account. It does not create or join an organization:
// the new user then either creates their own organization or accepts an invitation.
func (s *Service) Register(ctx context.Context, email, password, fullName string) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := s.validatePassword(password); err != nil {
		return User{}, err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, err
	}

	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		user, err = repo.CreateUser(ctx, email, hash, strings.TrimSpace(fullName))
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionUserRegistered,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": email},
		})
	})
	if err != nil {
		return User{}, err
	}

	// After the commit, so the token cannot outlive a rolled-back user. A send
	// failure is logged, not returned: registration must not fail because the mail
	// provider hiccuped, and they can always ask for another link.
	s.SendVerificationEmail(ctx, user)

	return user, nil
}

// ---------------------------------------------------------------- sessions

// Login verifies a password and issues a session token. The returned plaintext
// token is the only copy that will ever exist outside the client: the database
// stores its digest.
func (s *Service) Login(ctx context.Context, email, password string, meta RequestMeta) (string, User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Hash a dummy password anyway. Returning immediately here would make
			// a request for an unregistered email measurably faster than one for a
			// registered email, turning login timing into an account-enumeration
			// oracle -- which is exactly what the identical error message is meant
			// to prevent.
			_, _ = s.hasher.Hash(password)
			s.recordFailedLogin(ctx, email, nil, "unknown_email")
			return "", User{}, ErrInvalidCredentials
		}
		return "", User{}, err
	}

	// No password hash means an SSO-only account; it can never log in this way.
	if user.PasswordHash == "" || !user.IsActive {
		_, _ = s.hasher.Hash(password)

		reason := "deactivated"
		if user.PasswordHash == "" {
			reason = "no_password_set"
		}
		s.recordFailedLogin(ctx, email, &user.ID, reason)
		return "", User{}, ErrInvalidCredentials
	}

	if err := s.hasher.Verify(password, user.PasswordHash); err != nil {
		if errors.Is(err, auth.ErrMismatch) {
			s.recordFailedLogin(ctx, email, &user.ID, "wrong_password")
			return "", User{}, ErrInvalidCredentials
		}
		// A malformed stored hash is our bug, not the caller's. They still get
		// ErrInvalidCredentials, but we want to know about it.
		s.log.Error("stored password hash is unreadable",
			slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
		s.recordFailedLogin(ctx, email, &user.ID, "corrupt_hash")
		return "", User{}, ErrInvalidCredentials
	}

	// The password is correct and in hand -- the only moment we can transparently
	// upgrade a hash written under weaker parameters. Failure here is not worth
	// failing the login over.
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if newHash, err := s.hasher.Hash(password); err == nil {
			if err := s.repo.UpdateUserPassword(ctx, user.ID, newHash); err != nil {
				s.log.Warn("could not upgrade password hash",
					slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
			}
		}
	}

	plaintext, digest, err := auth.NewToken(auth.SessionTokenPrefix)
	if err != nil {
		return "", User{}, err
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if _, err := repo.CreateSession(ctx, user.ID, digest,
			time.Now().Add(s.cfg.SessionTTL), meta.UserAgent, meta.IPAddress); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionUserLoggedIn,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"ip": meta.IPAddress, "user_agent": meta.UserAgent},
		})
	})
	if err != nil {
		return "", User{}, err
	}

	return plaintext, user, nil
}

// recordFailedLogin writes an audit entry for a rejected login.
//
// The CALLER cannot tell a wrong password from an unknown email from a
// deactivated account -- that is deliberate, and it is what stops login from
// becoming an account-enumeration oracle. But the AUDIT LOG records exactly which
// it was, because you need to tell a customer's typo apart from somebody working
// through a password list.
//
// It is written on the pool, not in a transaction: there is no transaction here to
// join, and a failure to record must not turn a clean 401 into a 500. A failed
// audit write is logged and swallowed -- losing one entry is bad, but refusing to
// answer a login attempt because the audit table hiccuped is worse.
func (s *Service) recordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, reason string) {
	err := audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		ActorUserID: userID, // nil when the email matched nobody
		Action:      audit.ActionLoginFailed,
		TargetType:  "user",
		Metadata:    map[string]any{"email": email, "reason": reason},
	})
	if err != nil {
		s.log.Error("could not audit a failed login", slog.String("error", err.Error()))
	}
}

// Authenticate resolves a bearer token to the user it belongs to. This runs on
// every authenticated request, which is why it is a single indexed query.
func (s *Service) Authenticate(ctx context.Context, token string) (User, Session, error) {
	if token == "" {
		return User{}, Session{}, ErrUnauthenticated
	}
	return s.repo.AuthenticateSession(ctx, auth.HashToken(token))
}

// Logout revokes the session behind the given token. It is idempotent.
func (s *Service) Logout(ctx context.Context, token string, userID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSession(ctx, auth.HashToken(token)); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionUserLoggedOut,
			TargetType:  "user",
			TargetID:    userID.String(),
		})
	})
}

// ListSessions returns the caller's live sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	return s.repo.ListUserSessions(ctx, userID)
}

// RevokeSession kills ONE of the caller's sessions -- "sign out that other device".
//
// Listing your sessions and being unable to do anything about them was an odd
// half-feature: it showed you the compromise and offered no way to end it.
//
// The user id goes into the WHERE clause, so a caller cannot revoke somebody else's
// session by guessing its id.
func (s *Service) RevokeSession(ctx context.Context, actor User, sessionID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSessionByID(ctx, actor.ID, sessionID); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionSessionRevoked,
			TargetType:  "session",
			TargetID:    sessionID.String(),
		})
	})
}

// PurgeDeletedOrganizations hard-deletes organizations soft-deleted longer than retain ago.
//
// It runs in a transaction that sets app.audit_purge, because the cascade destroys
// the organization's audit entries too -- and the append-only trigger refuses any other
// DELETE against that table. Destroying an audit trail should take a deliberate act,
// and this is what one looks like.
func (s *Service) PurgeDeletedOrganizations(ctx context.Context, retain time.Duration) (int64, error) {
	if retain <= 0 {
		return 0, nil // keep forever: the default
	}

	var purged int64
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		var err error
		purged, err = NewRepository(db).PurgeDeletedOrganizations(ctx, retain)
		return err
	})
	return purged, err
}

// ChangePassword rotates a user's password and, in the same transaction, revokes
// every session they have -- including, deliberately, the one making this
// request. A password change that leaves an attacker's stolen session alive has
// achieved nothing.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, next string) error {
	if err := s.validatePassword(next); err != nil {
		return err
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash == "" {
		return ErrInvalidCredentials
	}
	if err := s.hasher.Verify(current, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	hash, err := s.hasher.Hash(next)
	if err != nil {
		return err
	}

	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.UpdateUserPassword(ctx, userID, hash); err != nil {
			return err
		}
		revoked, err := repo.RevokeUserSessions(ctx, userID)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionPasswordChanged,
			TargetType:  "user",
			TargetID:    userID.String(),
			Metadata:    map[string]any{"sessions_revoked": revoked},
		})
	})
}

// CleanupSessions deletes long-dead session rows. cmd/server runs it on a ticker.
func (s *Service) CleanupSessions(ctx context.Context, retain time.Duration) (int64, error) {
	return s.repo.DeleteDeadSessions(ctx, retain)
}

// ---------------------------------------------------------------- organizations

// CreateOrganization creates an organization and makes the caller its owner, atomically.
//
// The two must not be separable: a committed organization with no membership would be
// invisible and unadministrable by anyone, including the person who just made it.
func (s *Service) CreateOrganization(ctx context.Context, actor User, slug, name string) (Organization, error) {
	// The two gates on standing up an organization, and they exist for the same reason: an
	// account nobody has verified, creating organizations without limit, is free storage
	// for an abuser and a bill for you.
	if err := s.requireVerifiedEmail(actor); err != nil {
		return Organization{}, err
	}
	if s.cfg.MaxOrganizationsPerUser > 0 {
		n, err := s.repo.CountOrganizationsForUser(ctx, actor.ID)
		if err != nil {
			return Organization{}, err
		}
		if n >= s.cfg.MaxOrganizationsPerUser {
			return Organization{}, ErrTooManyOrganizations
		}
	}

	slug, err := normalizeSlug(slug)
	if err != nil {
		return Organization{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Organization{}, invalid("organization name is required")
	}

	var organization Organization
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		organization, err = repo.CreateOrganization(ctx, slug, name)
		if err != nil {
			return err
		}

		membership, err := repo.CreateMembership(ctx, actor.ID, organization.ID)
		if err != nil {
			return err
		}

		// Make the creator an owner. All three of these must commit together: a
		// organization with no owner, or a membership with no roles, is an organization nobody
		// -- including the person who just made it -- can administer.
		owner, err := repo.GetRoleByKey(ctx, organization.ID, RoleKeyOwner)
		if err != nil {
			return fmt.Errorf("identity: the system owner role is missing: %w", err)
		}
		if err := repo.SetMembershipRoles(ctx, membership.ID, []uuid.UUID{owner.ID}); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionOrganizationCreated,
			TargetType:     "organization",
			TargetID:       organization.ID.String(),
			Metadata:       map[string]any{"slug": slug, "name": name},
		})
	})
	if err != nil {
		return Organization{}, err
	}
	return organization, nil
}

// ListOrganizations returns the organizations the user belongs to, with their roles in each.
// Soft-deleted organizations are not among them.
func (s *Service) ListOrganizations(ctx context.Context, userID uuid.UUID) ([]OrganizationMembership, error) {
	return s.repo.ListOrganizationsForUser(ctx, userID)
}

// UpdateOrganization renames an organization. Requires organization.update.
//
// The name is the only field that changes. The slug is immutable -- see
// Organization.Slug -- and a request that tries to change it is rejected at the handler.
func (s *Service) UpdateOrganization(ctx context.Context, actor User, access OrganizationAccess, name string) (Organization, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Organization{}, invalid("organization name is required")
	}
	if len(name) > 200 {
		return Organization{}, invalid("organization name must be at most 200 characters")
	}

	var organization Organization
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		var err error
		organization, err = repo.UpdateOrganization(ctx, access.Organization.ID, name)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionOrganizationUpdated,
			TargetType:     "organization",
			TargetID:       access.Organization.ID.String(),
			Metadata:       map[string]any{"from": access.Organization.Name, "to": name},
		})
	})
	if err != nil {
		return Organization{}, err
	}
	return organization, nil
}

// DeleteOrganization soft-deletes an organization. Requires organization.delete, which only the
// owner role carries.
//
// The organization becomes invisible to everyone -- including its owners -- immediately.
// Nothing is destroyed: every membership, role, invitation, and audit entry stays,
// so a superuser can restore it whole.
//
// The audit entry is written to the organization that is being deleted, which is not
// contradictory: the audit log is not filtered by the organization's liveness, and a
// restored organization should have the record of its own deletion.
func (s *Service) DeleteOrganization(ctx context.Context, actor User, access OrganizationAccess) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.SoftDeleteOrganization(ctx, access.Organization.ID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionOrganizationDeleted,
			TargetType:     "organization",
			TargetID:       access.Organization.ID.String(),
			Metadata: map[string]any{
				"slug": access.Organization.Slug,
				"name": access.Organization.Name,
				// The slug is now free for anyone to claim. Record it, because if
				// somebody does, a later restore cannot have it back.
				"slug_released": true,
			},
		})
	})
}

// RestoreOrganization brings a soft-deleted organization back. Superuser only -- and it has to
// be, because a deleted organization 404s for its own owners, so nobody inside it can
// ask for it back.
//
// slug may be empty to keep the one it had. If that slug has since been claimed by
// a live organization, this returns ErrSlugTaken and the caller must supply another: the
// unique index has no room for two live organizations on one slug. Restore is always
// possible; it cannot always give you your old URL back.
func (s *Service) RestoreOrganization(ctx context.Context, actor User, organizationID uuid.UUID, slug string) (Organization, error) {
	var organization Organization

	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		deleted, err := repo.GetDeletedOrganization(ctx, organizationID)
		if err != nil {
			return err
		}

		// Default to the slug it had. It may no longer be available -- the unique
		// index will say so.
		target := deleted.Slug
		if slug != "" {
			if target, err = normalizeSlug(slug); err != nil {
				return err
			}
		}

		organization, err = repo.RestoreOrganization(ctx, organizationID, target)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionOrganizationRestored,
			TargetType:     "organization",
			TargetID:       organization.ID.String(),
			Metadata: map[string]any{
				"slug":          organization.Slug,
				"original_slug": deleted.Slug,
				"slug_changed":  organization.Slug != deleted.Slug,
			},
		})
	})
	if err != nil {
		return Organization{}, err
	}
	return organization, nil
}

// ResolveOrganization turns the slug in a request path into an organization plus the caller's
// authority in it. This is the authorization gate for every organization-scoped route,
// and the middleware in internal/server calls nothing else to make its decision.
//
// Access comes from one of two places, in this order:
//
//   - A membership row. The ordinary path: the role on that row is the answer.
//   - The global superuser flag. A superuser may enter ANY organization, as an implicit
//     owner, with no membership. OrganizationAccess.ViaSuperuser marks this, and the
//     middleware writes an audit entry for it -- see Service.RecordSuperuserAccess.
//
// A superuser who genuinely IS a member gets their real role and no bypass flag:
// there is nothing extraordinary about them using an organization they belong to, and
// auditing it would bury the accesses that matter in noise.
//
// An organization that does not exist and an organization the caller cannot see both return
// ErrNotFound, and must: a distinguishable "403 Forbidden" would let a stranger
// enumerate which organization slugs are taken.
func (s *Service) ResolveOrganization(ctx context.Context, user User, slug string) (OrganizationAccess, error) {
	organization, err := s.repo.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		// Note that a superuser gets ErrNotFound here too, for a slug that really
		// does not exist. The bypass grants entry to organizations, not to fictions.
		return OrganizationAccess{}, err
	}

	roles, err := s.repo.LoadMemberRoles(ctx, user.ID, organization.ID)
	switch {
	case err == nil:
		// The ordinary path: the caller's permissions are the union of every role
		// they hold here.
		return OrganizationAccess{
			Organization: organization,
			Roles:        roles,
			Permissions:  unionPermissions(roles),
		}, nil

	case errors.Is(err, ErrNotFound) && user.IsSuperuser:
		// The bypass. A superuser holds every permission in the catalog, so every
		// requirePermission check passes -- but they hold no ROLE, because they are
		// not a member of anything. ViaSuperuser records that, and the middleware
		// audits it.
		return OrganizationAccess{
			Organization: organization,
			Roles:        nil,
			Permissions:  AllPermissions(),
			ViaSuperuser: true,
		}, nil

	default:
		return OrganizationAccess{}, err // ErrNotFound: same answer as "no such organization"
	}
}

// RecordSuperuserAccess writes the audit entry for a superuser entering an organization
// they do not belong to. The middleware calls it on every such request.
//
// This is a database write on a read path, and that is the deliberate cost of the
// bypass: a superuser who can silently read any customer's data is a liability,
// and one who cannot do it unseen is merely powerful. If the write volume ever
// hurts, throttle it per (user, organization) the way sessions.last_used_at is
// throttled -- do not remove it.
func (s *Service) RecordSuperuserAccess(ctx context.Context, user User, organization Organization, method, path string) error {
	return audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		OrganizationID: &organization.ID,
		ActorUserID:    &user.ID,
		Action:         audit.ActionSuperuserOrganizationAccessed,
		TargetType:     "organization",
		TargetID:       organization.ID.String(),
		Metadata: map[string]any{
			"method": method,
			"path":   path,
			"email":  user.Email,
		},
	})
}

// ---------------------------------------------------------------- superuser

// ListAllOrganizations returns every organization in the installation. Superuser only: the
// route that reaches it sits behind requireSuperuser.
func (s *Service) ListAllOrganizations(ctx context.Context, before uuid.UUID, limit int) ([]OrganizationSummary, error) {
	return s.repo.ListAllOrganizations(ctx, before, limit)
}

// ListAllUsers returns every user in the installation. Superuser only.
func (s *Service) ListAllUsers(ctx context.Context, before uuid.UUID, limit int) ([]User, error) {
	return s.repo.ListAllUsers(ctx, before, limit)
}

// SetUserActive activates or deactivates a user globally, and -- when
// deactivating -- revokes every session they hold, in the same transaction.
//
// The revocation is the point. Flipping is_active alone would leave the user
// working normally until their token expired, which for the default 30-day TTL
// means "deactivated" would mean nothing for a month. With it, the lockout takes
// effect on their very next request.
func (s *Service) SetUserActive(ctx context.Context, actor User, targetUserID uuid.UUID, isActive bool) (User, error) {
	// A superuser deactivating themselves would lock the installation's operator
	// out of their own staff surface, and they are the only one who could undo it.
	if actor.ID == targetUserID && !isActive {
		return User{}, invalid("you cannot deactivate your own account")
	}

	var user User
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		var err error
		user, err = repo.SetUserActive(ctx, targetUserID, isActive)
		if err != nil {
			return err
		}

		action := audit.ActionUserReactivated
		metadata := map[string]any{"email": user.Email}

		if !isActive {
			revoked, err := repo.RevokeUserSessions(ctx, targetUserID)
			if err != nil {
				return err
			}
			action = audit.ActionUserDeactivated
			metadata["sessions_revoked"] = revoked
		}

		// OrganizationID is nil: this is an installation-wide action, not an organization one.
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      action,
			TargetType:  "user",
			TargetID:    targetUserID.String(),
			Metadata:    metadata,
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// SetSuperuser grants or revokes the global superuser flag. It is reachable only
// from the CLI (`server grant-superuser`), never over HTTP -- so acquiring the
// most powerful privilege in the system takes database access, not a stolen
// token, and a compromised superuser cannot mint more of itself.
//
// The audit entry has a NULL actor: there is no logged-in user behind a shell
// command. Who ran it is a question for your shell history and your ops logs.
func (s *Service) SetSuperuser(ctx context.Context, email string, isSuperuser bool) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}

	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		user, err = repo.SetSuperuser(ctx, email, isSuperuser)
		if err != nil {
			return err
		}

		action := audit.ActionSuperuserRevoked
		if isSuperuser {
			action = audit.ActionSuperuserGranted
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: nil, // the CLI has no logged-in actor
			Action:      action,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": user.Email, "via": "cli"},
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// ---------------------------------------------------------------- members

// ListMembers returns the organization's members.
func (s *Service) ListMembers(ctx context.Context, organizationID uuid.UUID) ([]Member, error) {
	return s.repo.ListMembers(ctx, organizationID)
}

// RemoveMember removes a user from an organization.
//
// Two rules, both of which also live in SetMemberRoles because they guard the
// same thing from a different direction: only an owner may remove an owner, and
// the last owner cannot be removed at all.
//
// Removing yourself is allowed -- that is how you leave an organization -- and is subject
// to the identical last-owner check, which is why the sole owner of an organization
// cannot walk out of it without appointing a successor first.
func (s *Service) RemoveMember(ctx context.Context, actor User, access OrganizationAccess, targetUserID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.LockOrganization(ctx, access.Organization.ID); err != nil {
			return err
		}

		targetRoles, err := repo.LoadMemberRoles(ctx, targetUserID, access.Organization.ID)
		if err != nil {
			return err
		}

		if hasOwnerRole(targetRoles) {
			// Removing an owner is an owner-level act. An admin holds
			// members.remove, so the permission check upstream already passed --
			// but permissions alone would let them evict someone strictly more
			// powerful than themselves.
			if !access.ViaSuperuser && !actorHoldsOwner(access) {
				return ErrForbidden
			}

			owners, err := repo.CountOwners(ctx, access.Organization.ID)
			if err != nil {
				return err
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}

		if err := repo.DeleteMembership(ctx, access.Organization.ID, targetUserID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionMemberRemoved,
			TargetType:     "user",
			TargetID:       targetUserID.String(),
			Metadata:       map[string]any{"roles": roleKeys(targetRoles)},
		})
	})
}

// ---------------------------------------------------------------- invitations

// Invite creates an invitation to join an organization and returns it along with the
// plaintext token. The token is returned exactly once, here: hand it to your
// mailer, put it in a link, and do not log it.
//
// The template does not send the email -- that is the one piece deliberately
// left to you, since every project's mailer differs. Wire it up where the
// handler returns.
// An invitation carries a ROLE, so issuing one is a way of handing out
// permissions -- and therefore takes the same escalation guard as creating a role
// or assigning one. Without it, an admin who cannot promote a member to owner
// could simply invite a fresh account as an owner and log in as it.
// THE TOKEN IS EMAILED AND NEVER RETURNED. It used to come back in the HTTP
// response, which was a hole with a plausible excuse: it made the template usable
// with no mailer -- and it meant any admin could mint a working invitation link
// for an address they did not control. carol@example.com's invitation, sitting in
// the admin's own hands, redeemable by whoever registers that address first. The
// only copy now goes to the invitee's inbox.
//
// In development the "inbox" is the application log (MAIL_BACKEND=log), which is
// exactly why startup refuses that backend in production.
func (s *Service) Invite(
	ctx context.Context, actor User, access OrganizationAccess, email string, roleID uuid.UUID,
) (Invitation, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return Invitation{}, err
	}

	// Resolving the role through the organization is what stops an admin of organization A
	// from inviting somebody into organization B's custom role by id.
	role, err := s.repo.GetRole(ctx, access.Organization.ID, roleID)
	if err != nil {
		return Invitation{}, err
	}
	if err := checkEscalation(access, role.Permissions); err != nil {
		return Invitation{}, err
	}

	// Already a member? Then there is nothing to invite them to.
	if existing, err := s.repo.GetUserByEmail(ctx, email); err == nil {
		if _, err := s.repo.GetMembership(ctx, existing.ID, access.Organization.ID); err == nil {
			return Invitation{}, ErrAlreadyMember
		} else if !errors.Is(err, ErrNotFound) {
			return Invitation{}, err
		}
	} else if !errors.Is(err, ErrNotFound) {
		return Invitation{}, err
	}

	plaintext, digest, err := auth.NewToken(auth.InvitationTokenPrefix)
	if err != nil {
		return Invitation{}, err
	}

	var inv Invitation
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Re-inviting somebody replaces their outstanding invitation rather than
		// colliding with the partial unique index on (organization_id, email). This also
		// invalidates the old link, which is the behaviour you want if the first
		// one went to the wrong address.
		if err := repo.RevokePendingInvitationFor(ctx, access.Organization.ID, email); err != nil {
			return err
		}

		id, err := repo.CreateInvitation(ctx, access.Organization.ID, email, role.ID, actor.ID, digest,
			time.Now().Add(s.cfg.InvitationTTL))
		if err != nil {
			return err
		}

		inv, err = repo.GetInvitation(ctx, id)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionInvitationCreated,
			TargetType:     "invitation",
			TargetID:       inv.ID.String(),
			Metadata:       map[string]any{"email": email, "role": role.Key},
		})
	})
	if err != nil {
		return Invitation{}, err
	}
	inv.TokenHash = digest

	// Send AFTER the commit. The other order would email a link to an invitation
	// that does not exist yet -- and could email one for an invitation that never
	// comes to exist, if the transaction then rolled back.
	msg := mail.Invitation(s.mailCfg.BaseURL, access.Organization.Name, actor.Email, plaintext)
	msg.To = email

	if err := s.mailer.Send(ctx, msg); err != nil {
		// The invitation is committed but the email did not go. Do NOT fail the
		// request: the admin would retry, and re-inviting revokes and reissues, so
		// they would generate a second dead token. Tell them the truth instead --
		// the invitation exists, and it can be resent.
		s.log.Error("invitation created but the email could not be sent",
			slog.String("email", email),
			slog.String("organization", access.Organization.Slug),
			slog.String("error", err.Error()),
		)
		return inv, ErrMailFailed
	}
	return inv, nil
}

// ListInvitations returns the organization's outstanding invitations.
func (s *Service) ListInvitations(ctx context.Context, organizationID uuid.UUID) ([]Invitation, error) {
	return s.repo.ListPendingInvitations(ctx, organizationID)
}

// RevokeInvitation withdraws a pending invitation, invalidating its link.
func (s *Service) RevokeInvitation(ctx context.Context, actor User, organization Organization, invitationID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.RevokeInvitation(ctx, organization.ID, invitationID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &organization.ID,
			ActorUserID:    &actor.ID,
			Action:         audit.ActionInvitationRevoked,
			TargetType:     "invitation",
			TargetID:       invitationID.String(),
		})
	})
}

// AcceptInvitation turns an invitation token into a membership for the logged-in
// caller.
//
// The invitation's email must match the caller's. Without that check, anyone who
// obtained an invitation link -- forwarded, leaked from an inbox, guessed from a
// screenshot -- could join an organization they were never invited to, as whatever role
// the invitation carried.
func (s *Service) AcceptInvitation(ctx context.Context, user User, token string) (Organization, error) {
	digest := auth.HashToken(token)

	var organization Organization
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		inv, err := repo.GetInvitationByTokenHash(ctx, digest)
		if err != nil {
			return err
		}
		if !inv.Pending(time.Now()) {
			return ErrInvitationInvalid
		}
		if !strings.EqualFold(inv.Email, user.Email) {
			// Deliberately indistinguishable from a bad token: telling the holder
			// of a leaked link "this is valid, but it is not for you" confirms both
			// that the organization exists and who was invited to it.
			return ErrInvitationInvalid
		}

		if err := repo.LockOrganization(ctx, inv.OrganizationID); err != nil {
			return err
		}

		// Marking the invitation accepted is guarded in SQL, so two concurrent
		// accepts of the same link cannot both create a membership: exactly one
		// updates a row, and the loser rolls back with ErrInvitationInvalid.
		if err := repo.AcceptInvitation(ctx, inv.ID); err != nil {
			return err
		}

		membership, err := repo.CreateMembership(ctx, user.ID, inv.OrganizationID)
		if err != nil {
			return err
		}
		// The membership and its role commit together: a member holding no roles
		// could see nothing, which is not what the invitation offered.
		if err := repo.SetMembershipRoles(ctx, membership.ID, []uuid.UUID{inv.Role.ID}); err != nil {
			return err
		}

		// Redeeming this token PROVES the user controls the address it was emailed
		// to -- AcceptInvitation already refuses unless the invitation's email
		// matches theirs. That is exactly what verification asks for, so asking them
		// to click a second link would be theatre.
		if err := markVerifiedByInvitation(ctx, db, user); err != nil {
			return err
		}

		if err := audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &inv.OrganizationID,
			ActorUserID:    &user.ID,
			Action:         audit.ActionInvitationClaimed,
			TargetType:     "invitation",
			TargetID:       inv.ID.String(),
			Metadata:       map[string]any{"role": inv.Role.Key},
		}); err != nil {
			return err
		}

		organization, err = repo.GetOrganizationByID(ctx, inv.OrganizationID)
		return err
	})
	if err != nil {
		return Organization{}, err
	}
	return organization, nil
}

// ---------------------------------------------------------------- validation

// slugPattern allows lowercase alphanumerics separated by single hyphens. It is
// what will appear in URLs, so it must be unambiguous and shell-safe.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// reservedSlugs cannot be taken by an organization, because they either already name a
// route or are ones you will want later. Reserving them costs nothing now and is
// impossible once somebody owns them.
var reservedSlugs = map[string]bool{
	"api": true, "auth": true, "admin": true, "app": true, "www": true,
	"static": true, "assets": true, "health": true, "healthz": true,
	"readyz": true, "metrics": true, "login": true, "logout": true,
	"register": true, "signup": true, "me": true, "settings": true,
	"support": true, "billing": true, "docs": true, "status": true,
	"new": true, "invitations": true, "organizations": true,
}

func normalizeSlug(slug string) (string, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	switch {
	case slug == "":
		return "", invalid("organization slug is required")
	case len(slug) < 2 || len(slug) > 63:
		return "", invalid("organization slug must be between 2 and 63 characters")
	case !slugPattern.MatchString(slug):
		return "", invalid("organization slug may contain only lowercase letters, digits, and single hyphens between them")
	case reservedSlugs[slug]:
		return "", invalid(fmt.Sprintf("organization slug %q is reserved", slug))
	}
	return slug, nil
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", invalid("email is required")
	}
	// net/mail accepts "Name <addr@example.com>"; we want the bare address only.
	addr, err := netmail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", invalid("email is not a valid address")
	}
	if len(email) > 254 { // RFC 5321 maximum
		return "", invalid("email is too long")
	}
	return email, nil
}

func (s *Service) validatePassword(password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return invalid(fmt.Sprintf("password must be at least %d characters", s.cfg.MinPasswordLength))
	}
	// argon2 itself has no length ceiling, but hashing a megabyte of input on
	// every login attempt is a free denial-of-service, so cap it.
	if len(password) > 1024 {
		return invalid("password must be at most 1024 characters")
	}
	return nil
}
