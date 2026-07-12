package identity

import "errors"

// The errors the service returns. The HTTP layer maps each to a status code in
// one place (see internal/server/response.go), so handlers never invent their
// own error semantics.
var (
	// ErrNotFound means the requested row does not exist -- or exists but the
	// caller has no membership granting them sight of it. The two are collapsed
	// on purpose: telling a stranger "this tenant exists, but not for you" leaks
	// which tenants exist.
	ErrNotFound = errors.New("identity: not found")

	// ErrInvalidCredentials is returned for a bad email, a bad password, and a
	// deactivated account alike. Never let the caller tell them apart: any
	// distinction is an oracle for enumerating registered accounts.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrUnauthenticated means no valid session token accompanied the request.
	ErrUnauthenticated = errors.New("identity: unauthenticated")

	// ErrForbidden means the caller is authenticated and is a member of the
	// tenant, but their role is too weak for this action.
	ErrForbidden = errors.New("identity: forbidden")

	// ErrEmailTaken is returned when registering an email that already has an
	// account. This is an unavoidable disclosure at the registration endpoint;
	// rate-limit it (see the README) rather than pretending to succeed.
	ErrEmailTaken = errors.New("identity: email already registered")

	// ErrSlugTaken is returned when creating a tenant whose slug is in use.
	ErrSlugTaken = errors.New("identity: tenant slug already taken")

	// ErrAlreadyMember is returned when inviting someone who already belongs to
	// the tenant.
	ErrAlreadyMember = errors.New("identity: user is already a member of this tenant")

	// ErrInvitationInvalid covers an invitation token that is unknown, already
	// accepted, revoked, or expired -- again collapsed, so a probe cannot learn
	// which.
	ErrInvitationInvalid = errors.New("identity: invitation is invalid or has expired")

	// ErrLastOwner is returned when removing the final owner of a tenant, or
	// stripping them of the owner role, which would leave it permanently
	// unadministrable -- nobody could grant roles or delete it.
	ErrLastOwner = errors.New("identity: cannot remove the last owner of a tenant")

	// ErrEscalation is THE RBAC guard. It is returned when a caller tries to grant
	// a permission they do not themselves hold -- by putting it in a role they are
	// creating or editing, or by assigning someone a role that carries it.
	//
	// Without this rule, RBAC defeats itself: anyone with roles.manage would simply
	// mint a role holding every permission and assign it to themselves. The same
	// rule also stops an admin assigning the system "owner" role, because owner
	// carries permissions an admin lacks -- no special case needed.
	ErrEscalation = errors.New("identity: you cannot grant a permission you do not hold")

	// ErrSystemRole is returned when trying to edit or delete a role the
	// application ships and depends on (owner, admin, member). They are immutable
	// so that a tenant cannot lock itself out -- by, say, stripping every
	// permission from "owner".
	ErrSystemRole = errors.New("identity: system roles cannot be modified or deleted")

	// ErrRoleInUse is returned when deleting a role that members still hold. The
	// caller must reassign them first; silently stripping people's access as a
	// side effect of a delete is not something to do quietly.
	ErrRoleInUse = errors.New("identity: this role is still assigned to members")

	// ErrRoleKeyTaken is returned when creating a role whose key the tenant
	// already uses -- including the keys of the system roles, which every tenant
	// shares.
	ErrRoleKeyTaken = errors.New("identity: a role with that key already exists")

	// ErrNoRoles is returned when a membership would be left holding no roles at
	// all, which is a member who can do nothing and see nothing -- almost certainly
	// a mistake rather than an intent. Remove them from the tenant instead.
	ErrNoRoles = errors.New("identity: a member must hold at least one role")

	// ErrInvalidToken covers a password-reset token that is unknown, already spent,
	// or expired -- collapsed, as ever, so a probe cannot learn which.
	ErrInvalidToken = errors.New("identity: this link is invalid or has expired")

	// ErrRateLimited means the caller has made too many attempts. It maps to 429.
	ErrRateLimited = errors.New("identity: too many attempts")

	// ErrMailFailed means the thing was created but the email announcing it did not
	// go out. It is NOT a failure of the operation: the invitation exists, and the
	// caller can resend it.
	//
	// It has its own error because the alternative -- failing the request -- would
	// be worse. The admin would retry, re-inviting revokes and reissues the token,
	// and they would accumulate dead invitations while still not knowing what went
	// wrong. A 502 that says "created, but the email did not send" is the honest
	// answer.
	ErrMailFailed = errors.New("identity: the email could not be sent")

	// ErrEmailNotVerified means the caller has not proved they control their email
	// address, and is trying to do the one thing that requires it: create a tenant.
	//
	// It gates tenant creation rather than login on purpose -- see User.EmailVerifiedAt.
	ErrEmailNotVerified = errors.New("identity: verify your email address first")

	// ErrTooManyTenants means the caller has hit MAX_TENANTS_PER_USER. Without a
	// cap, one account can stand up unlimited tenants, which is free storage and a
	// free abuse vector.
	ErrTooManyTenants = errors.New("identity: you have reached the maximum number of tenants")

	// ErrValidation is the base for input that is malformed. Wrap it with the
	// specific complaint (see validationError) so the message reaches the caller
	// while errors.Is still identifies the class.
	ErrValidation = errors.New("identity: validation failed")
)

// isNotFound is shorthand for errors.Is(err, ErrNotFound), which appears often
// enough in the service to be worth a name.
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// validationError carries a human-readable message while remaining detectable
// via errors.Is(err, ErrValidation).
type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }
func (e validationError) Is(target error) bool {
	return target == ErrValidation
}

func invalid(msg string) error { return validationError{msg: msg} }
