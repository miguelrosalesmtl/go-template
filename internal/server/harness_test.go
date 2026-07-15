package server

// HTTP-level tests for the server package.
//
// These drive the real chi handler with httptest -- no socket is opened -- against
// a real Postgres, exactly as the identity integration tests do. The point is to
// exercise what only exists at the HTTP layer and is therefore invisible to the
// service tests: the middleware chain (auth, organization resolution, permission
// checks, the superuser bypass), status-code mapping, security headers, CORS, the
// rate limiter, and request decoding.
//
// Like the identity suite, they SKIP without TEST_POSTGRES_DSN, so `go test ./...`
// still passes on a machine with no database. Run them with `make test-integration`.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	"github.com/miguelrosalesmtl/go-template/internal/identity"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
	"github.com/miguelrosalesmtl/go-template/migrations"
)

// testOrigin is the single allowed CORS origin the harness configures, so the
// CORS tests have both an allowed and (any other string) a disallowed case.
const testOrigin = "https://app.example.com"

// testPassword is long enough to clear MinPasswordLength in every test.
const testPassword = "correct-horse-battery-staple"

// suiteLockKey serializes the whole DB-backed suite against the identity suite.
//
// `go test ./...` builds one test binary per package and runs them as separate
// PROCESSES against the SAME test database. Both suites apply the migrations at
// startup AND wipe the shared tables between tests, so running at the same time,
// they race on CREATE EXTENSION and delete each other's rows. Holding a Postgres
// advisory lock for the entire run makes the two suites take turns instead. The
// identity harness takes the SAME key -- they must match to exclude each other.
const suiteLockKey = 918273645

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		// No database: every test calls requireDB and skips.
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

	// Exclude the identity suite for the whole run: they share this database and
	// both wipe it between tests. Acquired before migrating, so even startup does
	// not race.
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

// applyMigrations brings the test database to the current schema using the very
// migrations the app ships, so these tests can never drift from production's SQL.
func applyMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

// lockSuite acquires the suite-wide advisory lock and returns a release func. The
// lock lives on a dedicated single connection held open for the whole run, so the
// session-level lock persists until release. See suiteLockKey.
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

func requireDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("set TEST_POSTGRES_DSN to run integration tests (or run `make test-integration`)")
	}
}

// cleanDatabase empties the organization-owned tables, leaving the seeded system
// roles and the permission catalog. It mirrors internal/identity's cleanup,
// including the audit-purge dance the append-only trigger forces even on tests.
func cleanDatabase(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	err := database.InTx(ctx, testPool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		for _, stmt := range []string{
			`DELETE FROM audit_log`,
			`DELETE FROM membership_roles`,
			`DELETE FROM invitations`,
			`DELETE FROM memberships`,
			`DELETE FROM sessions`,
			`DELETE FROM password_resets`,
			`DELETE FROM email_verifications`,
			`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE organization_id IS NOT NULL)`,
			`DELETE FROM roles WHERE organization_id IS NOT NULL`,
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
}

// ---------------------------------------------------------------- mailer

// captureMailer records what the application tried to send, so a test can pull a
// token out of the link -- the only way to get one now that tokens are never
// returned over the API.
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

// ---------------------------------------------------------------- harness

// harness bundles a fully wired Server, its handler, and the pieces a test needs
// to reach around HTTP when setting up a scenario.
type harness struct {
	t       *testing.T
	svc     *identity.Service
	handler http.Handler
	mailer  *captureMailer
}

// newHarness builds a server on a clean database with rate limiting OFF (the
// common case; the limiter has its own test) and one allowed CORS origin.
func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, settings.RateLimit{Enabled: false})
}

// newHarnessWith builds a server with a specific rate-limit configuration.
func newHarnessWith(t *testing.T, rl settings.RateLimit) *harness {
	t.Helper()
	requireDB(t)
	cleanDatabase(t)

	mailer := &captureMailer{}
	svc := identity.NewService(
		testPool,
		testAuthSettings(),
		settings.Mail{BaseURL: "https://app.example.test"},
		mailer,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	srv := New(
		settings.Server{},
		rl,
		settings.CORS{AllowedOrigins: []string{testOrigin}},
		true, // debug: surface unexpected 500s in the test output
		svc,
		testPool,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	// Stop the limiter's reaper goroutine (if any) when the test ends.
	t.Cleanup(func() { close(srv.done) })

	return &harness{t: t, svc: svc, handler: srv.routes(), mailer: mailer}
}

// testAuthSettings turns argon2 down to the cheapest thing that still works, and
// switches off the email-verification gate and the organization cap so ordinary
// tests can create organizations freely. See internal/identity for the rationale.
func testAuthSettings() settings.Auth {
	return settings.Auth{
		SessionTTL:              720 * time.Hour,
		InvitationTTL:           168 * time.Hour,
		PasswordResetTTL:        1 * time.Hour,
		EmailVerifyTTL:          24 * time.Hour,
		MinPasswordLength:       12,
		RequireVerifiedEmail:    false,
		MaxOrganizationsPerUser: 0,
		ArgonMemoryKiB:          64,
		ArgonIterations:         1,
		ArgonParallelism:        1,
	}
}

// ---------------------------------------------------------------- requests

// req sends a request with an optional JSON body and bearer token, and returns
// the recorder. A nil body sends no body; a string body is sent verbatim (for
// testing malformed JSON); anything else is marshalled.
func (h *harness) req(method, path, token string, body any) *httptest.ResponseRecorder {
	h.t.Helper()

	var reader io.Reader
	switch b := body.(type) {
	case nil:
		reader = nil
	case string:
		reader = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	r := httptest.NewRequest(method, path, reader)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

// reqOrigin is like req but also sets an Origin header, for the CORS tests.
func (h *harness) reqOrigin(method, path, origin string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	return rec
}

// ---------------------------------------------------------------- scenario setup

// register creates a user over HTTP and returns its id.
func (h *harness) register(email string) uuid.UUID {
	h.t.Helper()
	rec := h.req(http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"email": email, "password": testPassword, "full_name": "Test User",
	})
	mustStatus(h.t, rec, http.StatusCreated)
	var u struct {
		ID uuid.UUID `json:"id"`
	}
	decodeBody(h.t, rec, &u)
	return u.ID
}

// login authenticates over HTTP and returns the session token.
func (h *harness) login(email string) string {
	h.t.Helper()
	rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": email, "password": testPassword,
	})
	mustStatus(h.t, rec, http.StatusOK)
	var resp struct {
		Token string `json:"token"`
	}
	decodeBody(h.t, rec, &resp)
	if resp.Token == "" {
		h.t.Fatal("login returned an empty token")
	}
	return resp.Token
}

// registerAndLogin is the common two-step, returning the token and user id.
func (h *harness) registerAndLogin(email string) (string, uuid.UUID) {
	h.t.Helper()
	id := h.register(email)
	return h.login(email), id
}

// makeSuperuser sets the global flag directly -- there is deliberately no HTTP
// route that can, which is the property the superuser tests rely on.
func (h *harness) makeSuperuser(email string) {
	h.t.Helper()
	if _, err := h.svc.SetSuperuser(context.Background(), email, true); err != nil {
		h.t.Fatalf("grant superuser to %s: %v", email, err)
	}
}

// createOrg creates an organization over HTTP and returns it.
func (h *harness) createOrg(token, slug, name string) identity.Organization {
	h.t.Helper()
	rec := h.req(http.MethodPost, "/api/v1/organizations", token, map[string]string{
		"slug": slug, "name": name,
	})
	mustStatus(h.t, rec, http.StatusCreated)
	var org identity.Organization
	decodeBody(h.t, rec, &org)
	return org
}

// roleID returns the id of a role by key, as visible to the token holder in slug.
func (h *harness) roleID(token, slug, key string) uuid.UUID {
	h.t.Helper()
	rec := h.req(http.MethodGet, "/api/v1/organizations/"+slug+"/roles", token, nil)
	mustStatus(h.t, rec, http.StatusOK)
	var resp struct {
		Roles []struct {
			ID  uuid.UUID `json:"id"`
			Key string    `json:"key"`
		} `json:"roles"`
	}
	decodeBody(h.t, rec, &resp)
	for _, r := range resp.Roles {
		if r.Key == key {
			return r.ID
		}
	}
	h.t.Fatalf("no role with key %q in %s", key, slug)
	return uuid.Nil
}

// ---------------------------------------------------------------- assertions

func mustStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, want, rec.Body.String())
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
}
