// Package identity owns users, organizations, memberships, roles, permissions,
// sessions, and invitations -- everything needed to answer "who is calling, and
// what may they do in this organization?".
//
// It is the part of the template you keep. Your product's own packages sit
// beside it and depend on it for the caller's identity, organization, and permissions.
package identity

import (
	"time"

	"github.com/google/uuid"
)

// Role is a named bundle of permissions, scoped to one organization.
//
// Roles are DATA: an organization administrator holding roles.manage creates and edits
// them at runtime. Permissions are CODE (see permissions.go). What you configure
// is which permissions a role bundles -- not which permissions exist.
//
// A role is one of two kinds:
//
//   - System (OrganizationID nil, IsSystem true): owner, admin, member. Ships with the
//     application, shared by every organization, and immutable through the API -- so a
//     organization cannot lock itself out by stripping every permission from "owner".
//   - Custom (OrganizationID set): belongs to exactly one organization, which may edit or
//     delete it. This is where "Billing Manager" lives.
type Role struct {
	ID uuid.UUID `json:"id"`
	// OrganizationID is nil for a system role, which every organization shares.
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	// Key is the stable identifier, e.g. "billing_manager". Unique per organization.
	Key string `json:"key"`
	// Name is the human label shown in a UI, e.g. "Billing Manager".
	Name string `json:"name"`
	// IsSystem marks a role the application depends on. Immutable through the API.
	IsSystem bool `json:"is_system"`
	// Permissions is what the role grants. The configurable part.
	Permissions PermissionSet `json:"permissions"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// The keys of the three system roles. They are strings, not a Role type: a role
// is now a row, and these merely name the ones the application ships with and
// depends on.
const (
	// RoleKeyOwner holds every permission. The last owner of an organization cannot be
	// removed or stripped of the role -- an organization with no owner would have nobody
	// able to grant roles or delete it.
	RoleKeyOwner = "owner"
	// RoleKeyAdmin is the organization administrator: everything except organization.delete.
	RoleKeyAdmin = "admin"
	// RoleKeyMember can see the organization and its members. Nothing more.
	RoleKeyMember = "member"
)

// User is a global identity. Users are deliberately not owned by an organization: the
// same person can be an owner of one organization and a member of another, under one
// account and one password.
type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`

	// IsSuperuser is the only global privilege in the system -- the operator of
	// the whole installation, not of any one organization. It grants two things:
	//
	//   1. The staff surface at /api/v1/admin: list every organization and user,
	//      deactivate an account.
	//   2. Entry into ANY organization without a membership, holding every permission
	//      in the catalog.
	//
	// The second is deliberately powerful and deliberately expensive: every such
	// entry writes a superuser.organization_accessed entry to the audit log, so a
	// superuser reading a customer's data can never do so unseen.
	//
	// It cannot be granted over HTTP. The only way to set it is the CLI
	// (`server grant-superuser <email>`), which requires database access.
	IsSuperuser bool `json:"is_superuser"`

	// IsActive gates login and every authenticated request: deactivating a user
	// takes effect on their very next request, because the session lookup joins
	// against it.
	IsActive bool `json:"is_active"`

	// EmailVerifiedAt is when the user proved they control the address -- by
	// clicking a link sent to it, or by redeeming an invitation that was emailed
	// there, which is the same proof by a different route.
	//
	// It gates ORGANIZATION CREATION, not login. Locking somebody out of their own
	// account because a verification email went to spam is a support nightmare for
	// very little gain; stopping an unverified address from standing up organizations is
	// the control that actually matters, and it doubles as abuse prevention.
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// PasswordHash never leaves the process: it is json:"-" so that a User can
	// be handed straight to an HTTP response encoder without leaking it.
	PasswordHash string `json:"-"`
}

// IsVerified reports whether the user has proved control of their email address.
func (u User) IsVerified() bool { return u.EmailVerifiedAt != nil }

// OrganizationAccess is the answer to "may this user act in this organization, and how?".
// It is what the organization middleware puts on the request context, and the only
// thing a handler needs to consult.
//
// Permissions is the union of every role the caller holds here. That union is
// the whole reason a member can hold several roles: "Member" plus "Billing
// Manager" is a person who can do both, without anyone having to invent a
// "Member Who Also Does Billing" role.
type OrganizationAccess struct {
	Organization Organization `json:"organization"`
	// Roles are the roles the caller holds in this organization, for display.
	Roles []Role `json:"roles"`
	// Permissions is the union of those roles' permissions. Every authorization
	// check reads this and nothing else.
	Permissions PermissionSet `json:"permissions"`
	// ViaSuperuser reports that access came from the global superuser flag rather
	// than from a membership. Permissions is then the entire catalog, and Roles is
	// empty -- a superuser holds no role, they simply outrank the question.
	//
	// It is separate from Permissions on purpose: a superuser's access must remain
	// distinguishable from a genuine owner's, or it could not be audited.
	ViaSuperuser bool `json:"via_superuser,omitempty"`
}

// Can reports whether the caller may perform p in this organization. This is the single
// question every authorization check in the application asks.
func (a OrganizationAccess) Can(p Permission) bool {
	return a.Permissions.Has(p)
}

// Organization is an isolated account. Every organization-owned row in the database carries
// an organization_id pointing here, and every query for such a row filters on it.
type Organization struct {
	ID uuid.UUID `json:"id"`
	// Slug appears in every URL. It is IMMUTABLE: it lives in your customers'
	// bookmarks, saved API calls, and webhook configuration, and changing it would
	// break all of them silently. Rename the Name instead.
	Slug string `json:"slug"`
	Name string `json:"name"`

	// DeletedAt marks a soft-deleted organization. When set, the organization 404s for
	// EVERYONE -- its owners included -- and disappears from "my organizations", because
	// every query in the repository filters `deleted_at IS NULL`. No data is
	// destroyed, so a superuser can restore it whole.
	//
	// It is nil in almost every response, since almost every query excludes
	// deleted organizations. The exception is the superuser staff surface, which lists
	// them precisely so that one can be found and restored.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsDeleted reports whether the organization has been soft-deleted.
func (t Organization) IsDeleted() bool { return t.DeletedAt != nil }

// OrganizationSummary is an organization plus its member count -- what the superuser staff
// surface lists. Ordinary users never see it: they get only the organizations they
// belong to, via OrganizationMembership.
type OrganizationSummary struct {
	Organization Organization `json:"organization"`
	MemberCount  int          `json:"member_count"`
}

// Membership links a user to an organization. Its absence is what denies access: there
// is no "public" organization data.
//
// The membership itself no longer carries a role -- roles hang off it in
// membership_roles, because a member may hold several.
type Membership struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Member is a membership joined with the user it points at and the roles they
// hold -- what the "list this organization's members" endpoint returns.
type Member struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
	Roles    []Role    `json:"roles"`
	// Permissions is the union of the member's roles, so a UI can show what
	// somebody can actually do without recomputing it.
	Permissions PermissionSet `json:"permissions"`
	JoinedAt    time.Time     `json:"joined_at"`
}

// OrganizationMembership is an organization joined with the caller's roles in it -- what "list
// the organizations I belong to" returns.
type OrganizationMembership struct {
	Organization Organization `json:"organization"`
	Roles        []Role       `json:"roles"`
}

// Session is a live login. The plaintext token exists only in the login response
// and in the client's hands; this struct holds its digest.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	UserAgent  string     `json:"user_agent"`
	IPAddress  string     `json:"ip_address,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	TokenHash []byte `json:"-"`
}

// Invitation is a pending offer to join an organization, addressed to an email that may
// not have a user account yet. Accepting it is what creates the membership.
//
// It points at a role row rather than carrying a role string, so an organization can
// invite somebody directly into one of its own custom roles.
type Invitation struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Email          string     `json:"email"`
	Role           Role       `json:"role"`
	InvitedBy      *uuid.UUID `json:"invited_by,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`

	TokenHash []byte `json:"-"`
}

// Pending reports whether the invitation can still be accepted: not already
// accepted, not revoked, not expired.
func (i Invitation) Pending(now time.Time) bool {
	return i.AcceptedAt == nil && i.RevokedAt == nil && i.ExpiresAt.After(now)
}

// unionPermissions returns the combined permissions of a set of roles. This is
// what a member "can do": hold two roles, get both their powers.
func unionPermissions(roles []Role) PermissionSet {
	out := PermissionSet{}
	for _, r := range roles {
		for p := range r.Permissions {
			out[p] = struct{}{}
		}
	}
	return out
}
