package identity

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
	"github.com/miguelrosalesmtl/go-template/migrations"
)

// These are integration tests: they run against a real Postgres, because what
// they are checking IS the SQL. A mocked database would happily "prove" that a
// query with a missing organization_id filter is correctly isolated, which is exactly
// the bug they exist to catch.
//
// Run them with:  make test-integration
//
// Without TEST_POSTGRES_DSN they skip, so `go test ./...` still passes on a
// machine with no database.
var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		// Nothing to run against. The individual tests call requireDB and skip.
		os.Exit(m.Run())
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to TEST_POSTGRES_DSN: %v\n", err)
		os.Exit(1)
	}
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ping TEST_POSTGRES_DSN: %v\n", err)
		os.Exit(1)
	}
	testPool = pool

	// The server suite shares this database and wipes it between tests just as this
	// one does, so under `go test ./...` (one process per package) they must not run
	// at the same time. Hold a suite-wide advisory lock for the whole run; the server
	// harness takes the SAME key. Acquired before migrating, so startup cannot race
	// either.
	unlock := lockSuite(dsn)

	if err := applyMigrations(dsn); err != nil {
		unlock()
		fmt.Fprintf(os.Stderr, "apply migrations: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	unlock()
	pool.Close()
	os.Exit(code)
}

// suiteLockKey serializes this suite against the server suite; see the identical
// constant and lockSuite in internal/server. They MUST match to exclude each other.
const suiteLockKey = 918273645

// lockSuite acquires the suite-wide advisory lock and returns a release func. The
// lock is held on a dedicated single connection kept open for the whole run.
func lockSuite(dsn string) func() {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lock suite: open: %v\n", err)
		os.Exit(1)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`SELECT pg_advisory_lock($1)`, suiteLockKey); err != nil {
		fmt.Fprintf(os.Stderr, "lock suite: %v\n", err)
		os.Exit(1)
	}
	return func() {
		_, _ = db.Exec(`SELECT pg_advisory_unlock($1)`, suiteLockKey)
		_ = db.Close()
	}
}

// applyMigrations brings the test database up to the current schema, using the
// very same embedded migrations the application ships. Tests therefore run
// against the schema that production will have -- not a hand-maintained copy of
// it that can silently drift.
func applyMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger()) // migrations are not the test output
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

// requireDB skips the test when no database is configured.
func requireDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("set TEST_POSTGRES_DSN to run integration tests (or run `make test-integration`)")
	}
}

// newTestService returns a Service on a clean database.
//
// Cleaning up front rather than after means a failed test leaves its rows behind
// for you to inspect.
//
// These are explicit, ordered DELETEs rather than a TRUNCATE ... CASCADE, and
// that is not fussiness. TRUNCATE CASCADE truncates every table that references
// the target -- the whole TABLE, not merely the referencing rows -- so
// `TRUNCATE organizations CASCADE` would empty `roles`, taking the seeded SYSTEM roles
// and, through them, the permission catalog's grants with it. Every subsequent
// test would then fail to find the owner role.
//
// So: delete the organization-owned data, and leave the catalog and the system roles
// (organization_id IS NULL) exactly as the migration seeded them.
func newTestService(t *testing.T) *Service {
	t.Helper()
	requireDB(t)
	testMailer.reset()

	ctx := context.Background()

	// THE WHOLE CLEANUP RUNS INSIDE THE SANCTIONED AUDIT-PURGE TRANSACTION, and it
	// has to -- which is itself a useful demonstration of how tightly the audit log
	// is now nailed down:
	//
	//   * `DELETE FROM audit_log` is refused outright by the trigger.
	//   * `DELETE FROM organizations` CASCADES into audit_log, so it is refused too.
	//   * `DELETE FROM users` sets audit_log.actor_user_id to NULL, which is an
	//     UPDATE -- permitted, but only because the trigger makes a precise
	//     exception for that one anonymising change.
	//
	// So even the tests must announce themselves with app.audit_purge before they
	// can erase history. That is mildly annoying here, and it is exactly the point:
	// if a test could quietly wipe the audit log, so could anything else.
	err := database.InTx(ctx, testPool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}

		// Order matters: membership_roles.role_id is ON DELETE RESTRICT, so the
		// assignments must go before the custom roles they point at.
		for _, stmt := range []string{
			`DELETE FROM audit_log`,
			`DELETE FROM membership_roles`,
			`DELETE FROM invitations`,
			`DELETE FROM memberships`,
			`DELETE FROM sessions`,
			`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE organization_id IS NOT NULL)`,
			`DELETE FROM roles WHERE organization_id IS NOT NULL`, // custom roles only; keep the system ones
			`DELETE FROM organizations`,
			`DELETE FROM users`,
		} {
			if _, err := db.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("clean database: %v", err)
	}

	return NewService(
		testPool,
		testAuthSettings(),
		settings.Mail{BaseURL: "https://app.example.test"},
		testMailer,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// testMailer captures what the application tried to send, so the tests can assert
// on the LINK -- which, now that tokens are never returned over the API, is the
// only way to get one.
//
// It is package-level and reset by newTestService, because the service takes the
// mailer at construction and every test builds its service the same way.
var testMailer = &captureMailer{}

type captureMailer struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (m *captureMailer) Send(_ context.Context, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *captureMailer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = nil
}

// lastTo returns the most recent message sent to an address.
func (m *captureMailer) lastTo(t *testing.T, email string) mail.Message {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == email {
			return m.sent[i]
		}
	}
	t.Fatalf("no email was sent to %s (sent: %d)", email, len(m.sent))
	return mail.Message{}
}

// tokenFromLink pulls the token out of the link in an email body. This is exactly
// what a user does when they click it.
func tokenFromLink(t *testing.T, body string) string {
	t.Helper()

	i := strings.Index(body, "token=")
	if i < 0 {
		t.Fatalf("no token= in the email body:\n%s", body)
	}
	tok := body[i+len("token="):]
	if j := strings.IndexAny(tok, " \n\t"); j >= 0 {
		tok = tok[:j]
	}
	if tok == "" {
		t.Fatalf("empty token in the email body:\n%s", body)
	}
	return tok
}

// ---------------------------------------------------------------- RBAC helpers

// accessFor resolves a user's authority in an organization, exactly as the HTTP
// middleware does. Every RBAC rule takes an OrganizationAccess, so the tests build one
// the same way production does rather than fabricating it.
func accessFor(t *testing.T, svc *Service, user User, slug string) OrganizationAccess {
	t.Helper()

	access, err := svc.ResolveOrganization(context.Background(), user, slug)
	if err != nil {
		t.Fatalf("resolve %s for %s: %v", slug, user.Email, err)
	}
	return access
}

// systemRoleID returns the id of one of the three system roles, which every
// organization shares.
func systemRoleID(t *testing.T, svc *Service, organizationID uuid.UUID, key string) uuid.UUID {
	t.Helper()

	role, err := svc.repo.GetRoleByKey(context.Background(), organizationID, key)
	if err != nil {
		t.Fatalf("get system role %q: %v", key, err)
	}
	return role.ID
}

// testAuthSettings mirrors the production settings but with argon2 turned down
// to the cheapest thing that still works. The tests here hash a password on
// every login, and the real 19 MiB / t=2 cost would make them take minutes.
//
// This is the ONLY place these numbers are acceptable. See settings.Auth.
func testAuthSettings() settings.Auth {
	return settings.Auth{
		SessionTTL:        720 * time.Hour, // 30 days
		InvitationTTL:     168 * time.Hour, // 7 days
		PasswordResetTTL:  1 * time.Hour,
		EmailVerifyTTL:    24 * time.Hour,
		MinPasswordLength: 12,
		// The tests create organizations constantly, so the gate and the cap must be off
		// unless a test is specifically exercising them (which TestEmailVerification
		// and TestOrganizationCap do, with their own settings).
		RequireVerifiedEmail:    false,
		MaxOrganizationsPerUser: 0,
		ArgonMemoryKiB:          64,
		ArgonIterations:         1,
		ArgonParallelism:        1,
	}
}
