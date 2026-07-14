// Package audit records an append-only history of who did what, in which organization,
// from where, and in which request.
//
// Nothing in this package updates or deletes, and a database trigger (migration
// 00009) refuses both if anything tries.
//
// BE CLEAR ABOUT WHAT THAT TRIGGER IS WORTH. It catches mistakes -- a careless
// query, a bad migration, an injected DELETE. It does NOT make the log tamper-proof
// against an attacker who already controls the application process, because the
// trigger permits a DELETE to anything that sets a GUC, and any role can set that
// GUC. Code running as the app can simply set it and delete.
//
// Real tamper-resistance needs two database identities: one that may destroy
// history, and a restricted one that the app connects as, holding no DELETE here.
// This template deliberately runs a SINGLE user that owns the database -- one
// secret, one connection string -- and accepts the consequence. If you need the
// stronger guarantee, that is the change to make, and it is not a large one.
//
// The log records DENIALS as well as successes. That is what turns it from a
// change-history into a security trail: an attacker probing your permission
// boundaries, or working through a password list, leaves a trace instead of
// silence. See the Action constants below, and internal/server/response.go, where
// every refusal in the application passes through one function.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// Action names the thing that happened, as "<resource>.<verb-in-past-tense>".
//
// The resource half deliberately matches the permission catalog in
// internal/identity: the permission is roles.create, the event is roles.created.
// So "roles.*" greps both what somebody may do and everything they did do, which
// is exactly the question an incident asks.
//
// Keep these strings stable. They end up in dashboards, alerts, and compliance
// exports, and renaming one orphans every row written under the old name.
type Action string

const (
	// --- Identity ---
	ActionUserRegistered  Action = "users.registered"
	ActionUserLoggedIn    Action = "users.logged_in"
	ActionUserLoggedOut   Action = "users.logged_out"
	ActionPasswordChanged Action = "users.password_changed"
	// Password reset. The REQUESTED and RESET pair bracket the flow; REJECTED is
	// the one to watch -- a burst of rejected requests against addresses that do not
	// exist is somebody enumerating your user list through an unauthenticated
	// endpoint.
	ActionPasswordResetRequested Action = "users.password_reset_requested"
	ActionPasswordResetRejected  Action = "users.password_reset_rejected"
	ActionPasswordReset          Action = "users.password_reset"
	ActionEmailVerified          Action = "users.email_verified"
	ActionSessionRevoked         Action = "users.session_revoked"
	ActionOrganizationPurged     Action = "organizations.purged" // hard delete; irreversible

	// --- Organizations ---
	ActionOrganizationCreated  Action = "organizations.created"
	ActionOrganizationUpdated  Action = "organizations.updated"
	ActionOrganizationDeleted  Action = "organizations.deleted"  // soft: restorable
	ActionOrganizationRestored Action = "organizations.restored" // superuser only

	// --- Members and invitations ---
	ActionInvitationCreated Action = "invitations.created"
	ActionInvitationRevoked Action = "invitations.revoked"
	ActionInvitationClaimed Action = "invitations.claimed" // accepted; a member joined
	ActionMemberUpdated     Action = "members.updated"     // their roles changed
	ActionMemberRemoved     Action = "members.removed"

	// --- RBAC ---
	// These change who can do what, so they are the ones worth reviewing: a role
	// quietly gaining a permission is how privilege creeps. Each carries the
	// before and after in its metadata.
	ActionRoleCreated Action = "roles.created"
	ActionRoleUpdated Action = "roles.updated"
	ActionRoleDeleted Action = "roles.deleted"

	// --- Superuser ---
	// The only ways a person can act outside the organizations they belong to. If you
	// alert on one thing in this list, alert on ActionSuperuserOrganizationAccessed.
	ActionSuperuserOrganizationAccessed Action = "superuser.organization_accessed"
	ActionSuperuserGranted              Action = "superuser.granted" // CLI only; actor is NULL
	ActionSuperuserRevoked              Action = "superuser.revoked"
	ActionUserDeactivated               Action = "users.deactivated"
	ActionUserReactivated               Action = "users.reactivated"

	// --- DENIALS ---
	//
	// The half of the story the log used to miss entirely. Without these, somebody
	// walking a password list, or systematically probing which permissions they
	// have, produces no record at all -- and "nothing in the audit log" reads
	// identically to "nothing happened".

	// ActionLoginFailed is a wrong password, an unknown email, or a deactivated
	// account. The three are indistinguishable to the CALLER, on purpose, but the
	// audit entry records which it was: you need to tell a typo from an attack.
	ActionLoginFailed Action = "users.login_failed"
	// ActionAccessDenied is a 403: the caller was authenticated and a member, but
	// lacked the permission the route required. A burst of these from one user is
	// somebody mapping your authorization boundaries.
	ActionAccessDenied Action = "access.denied"
	// ActionEscalationDenied is the RBAC guard firing: an attempt to grant a
	// permission the actor does not hold. This one is rarely innocent.
	ActionEscalationDenied Action = "access.escalation_denied"
	// ActionInvitationRejected is a bad, spent, expired, or misaddressed invitation
	// token -- including somebody trying to redeem a link that was not theirs.
	ActionInvitationRejected Action = "invitations.rejected"
	// ActionRateLimited is a caller being turned away by the limiter. One is noise;
	// a stream of them from a single IP is an attack in progress.
	ActionRateLimited Action = "access.rate_limited"
)

// Entry is one recorded event.
type Entry struct {
	ID             uuid.UUID      `json:"id"`
	OrganizationID *uuid.UUID     `json:"organization_id,omitempty"`
	ActorUserID    *uuid.UUID     `json:"actor_user_id,omitempty"`
	Action         Action         `json:"action"`
	TargetType     string         `json:"target_type,omitempty"`
	TargetID       string         `json:"target_id,omitempty"`
	Metadata       map[string]any `json:"metadata"`

	// RequestID ties the entry back to the HTTP request that caused it, and so to
	// every application log line for that request. The first thing you want in an
	// incident.
	RequestID string `json:"request_id,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Event is what a caller hands to Record.
//
// OrganizationID and ActorUserID are pointers because plenty of events have neither: a
// registration happens before the user belongs to any organization, a failed login has
// no established actor at all, and a CLI grant has no logged-in user behind it.
type Event struct {
	OrganizationID *uuid.UUID
	ActorUserID    *uuid.UUID
	Action         Action
	TargetType     string
	TargetID       string
	Metadata       map[string]any

	RequestID string
	IPAddress string
	UserAgent string
}

// ---------------------------------------------------------------- request meta

// RequestMeta is the ambient information about the HTTP request an action came in
// on. It rides the context rather than being threaded through every service
// signature.
//
// That is a deliberate exception to "pass dependencies explicitly". Request id,
// IP, and user agent are wanted on EVERY audit entry, they are wanted nowhere
// else, and threading them through would mean adding a parameter to a dozen
// service methods -- most of which would do nothing but forward it. Context is
// what it is for: ambient, request-scoped, cross-cutting.
type RequestMeta struct {
	RequestID string
	IPAddress string
	UserAgent string
}

type contextKey int

const metaKey contextKey = 0

// WithRequestMeta attaches request metadata to the context. The HTTP middleware
// calls it once, and every audit entry written during that request picks it up.
func WithRequestMeta(ctx context.Context, m RequestMeta) context.Context {
	return context.WithValue(ctx, metaKey, m)
}

// requestMetaFrom returns the metadata on the context, or the zero value. It is
// deliberately forgiving: an audit entry written from the CLI, or from a
// background job, simply has no request behind it, and that is not an error.
func requestMetaFrom(ctx context.Context) RequestMeta {
	m, _ := ctx.Value(metaKey).(RequestMeta)
	return m
}

// Recorder writes and reads audit entries.
type Recorder struct {
	db database.DB
}

// NewRecorder returns a Recorder backed by db.
//
// Pass a pgx.Tx to make the audit entry part of the same transaction as the
// change it describes. That is almost always what you want for a SUCCESS: it
// makes it impossible to perform an action and fail to log it, or to log one that
// then got rolled back.
//
// It is exactly what you must NOT do for a DENIAL. A refusal aborts its
// transaction, and an audit entry written inside that transaction would be rolled
// back along with the failure it was recording -- leaving no trace of precisely
// the events you most wanted to see. Denials are recorded on the pool, after the
// rollback; see internal/server/response.go.
func NewRecorder(db database.DB) *Recorder {
	return &Recorder{db: db}
}

// Record appends an entry.
//
// The request id, IP, and user agent are taken from the context when the caller
// has not set them explicitly -- so every audit write in the application gets
// them, without a single service method having to know they exist.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	meta := requestMetaFrom(ctx)
	if e.RequestID == "" {
		e.RequestID = meta.RequestID
	}
	if e.IPAddress == "" {
		e.IPAddress = meta.IPAddress
	}
	if e.UserAgent == "" {
		e.UserAgent = meta.UserAgent
	}

	metadata := e.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	// The User-Agent is attacker-controlled and lands in a text column. Cap it:
	// nobody needs 8KB of it, and this is a table that never forgets.
	ua := e.UserAgent
	if len(ua) > 512 {
		ua = ua[:512]
	}

	_, err = r.db.Exec(ctx,
		`INSERT INTO audit_log
		     (organization_id, actor_user_id, action, target_type, target_id, metadata,
		      request_id, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.OrganizationID, e.ActorUserID, e.Action, e.TargetType, e.TargetID, raw,
		e.RequestID, parseIP(e.IPAddress), ua,
	)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Action, err)
	}
	return nil
}

// Filter narrows a listing. The zero value matches everything in the organization.
type Filter struct {
	// Action, if set, matches one exact action ("roles.created").
	Action Action
	// ActorUserID, if set, matches everything one person did.
	ActorUserID *uuid.UUID
	// From and To bound created_at. Either may be zero.
	From, To time.Time
	// Before is the keyset cursor: pass the id of the last entry you received to
	// get the next page. Zero starts at the newest.
	Before uuid.UUID
	// Limit defaults to 50 and is capped at 200.
	Limit int
}

// List returns an organization's entries, newest first.
//
// Pagination is keyset, not OFFSET. Because ids are uuidv7 and therefore ordered
// by creation time, "id < before" means "older than" -- so a page is an index
// walk with no sort, page 100 costs what page 1 costs, and a row arriving
// mid-scroll cannot shift the pages under the reader. OFFSET fails all three.
func (r *Recorder) List(ctx context.Context, organizationID uuid.UUID, f Filter) ([]Entry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	// Every filter is expressed as "$n IS NULL OR <predicate>", so one prepared
	// statement serves every combination -- rather than concatenating SQL, which
	// is how injection bugs and unplannable queries both get in.
	var actor, before any
	if f.ActorUserID != nil {
		actor = *f.ActorUserID
	}
	if f.Before != uuid.Nil {
		before = f.Before
	}
	var action any
	if f.Action != "" {
		action = string(f.Action)
	}
	var from, to any
	if !f.From.IsZero() {
		from = f.From
	}
	if !f.To.IsZero() {
		to = f.To
	}

	rows, err := r.db.Query(ctx,
		`SELECT id, organization_id, actor_user_id, action, target_type, target_id, metadata,
		        request_id, ip_address, user_agent, created_at
		 FROM audit_log
		 WHERE organization_id = $1
		   AND ($2::uuid IS NULL OR id < $2::uuid)
		   AND ($3::text IS NULL OR action = $3::text)
		   AND ($4::uuid IS NULL OR actor_user_id = $4::uuid)
		   AND ($5::timestamptz IS NULL OR created_at >= $5::timestamptz)
		   AND ($6::timestamptz IS NULL OR created_at <= $6::timestamptz)
		 ORDER BY id DESC
		 LIMIT $7`,
		organizationID, before, action, actor, from, to, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	return collectEntries(rows)
}

// Purge permanently deletes entries older than retain. It is the ONLY caller
// permitted to delete from audit_log, and it announces itself to the trigger by
// setting app.audit_purge for the duration of its transaction.
//
// retain <= 0 means "keep forever", which is the default: the retention policy is
// yours to choose, and quietly destroying somebody's compliance evidence because
// a config value defaulted to 90 days is not a decision this template will make
// for you.
func (r *Recorder) Purge(ctx context.Context, retain time.Duration) (int64, error) {
	if retain <= 0 {
		return 0, nil
	}

	// The trigger from migration 00009 rejects every DELETE unless this is set. It
	// is transaction-local (SET LOCAL), so it cannot leak into another statement
	// on a pooled connection.
	if _, err := r.db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
		return 0, fmt.Errorf("audit: enable purge: %w", err)
	}

	tag, err := r.db.Exec(ctx,
		`DELETE FROM audit_log WHERE created_at < now() - make_interval(secs => $1)`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("audit: purge: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- scanning

func collectEntries(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
},
) ([]Entry, error) {
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var raw []byte
		var ip *netip.Addr

		if err := rows.Scan(
			&e.ID, &e.OrganizationID, &e.ActorUserID, &e.Action,
			&e.TargetType, &e.TargetID, &raw,
			&e.RequestID, &ip, &e.UserAgent, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit: scan entry: %w", err)
		}
		if err := json.Unmarshal(raw, &e.Metadata); err != nil {
			return nil, fmt.Errorf("audit: unmarshal metadata: %w", err)
		}
		if ip != nil {
			e.IPAddress = ip.String()
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate entries: %w", err)
	}
	return out, nil
}

// parseIP converts a client IP into the *netip.Addr pgx encodes into an inet
// column, or nil for NULL. A malformed address becomes NULL rather than an error:
// we are not going to fail an audit write -- least of all a denial -- because a
// proxy sent a header we could not parse.
func parseIP(s string) *netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}
