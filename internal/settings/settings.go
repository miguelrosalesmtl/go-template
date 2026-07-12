// Package settings loads and holds all application configuration.
//
// It works like Django's settings module: a single, typed, immutable object
// that is populated once at startup from environment variables (optionally
// seeded from a .env file) and then passed explicitly to the components that
// need it. Nothing else in the codebase should read os.Getenv directly.
package settings

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Settings is the fully-resolved configuration for a single process.
type Settings struct {
	App       App
	Server    Server
	Postgres  Postgres
	Auth      Auth
	Audit     Audit
	Tenant    Tenant
	CORS      CORS
	Mail      Mail
	RateLimit RateLimit
}

// Mail configures how invitation and password-reset email is sent.
type Mail struct {
	// Backend is "log" or "smtp".
	//
	// "log" prints the whole email, link and all, to the application log. That is
	// what makes the template runnable with no setup -- and it is why startup
	// REFUSES it in production: invitation and reset links in your logs are
	// working credentials in your logs.
	Backend string `env:"MAIL_BACKEND" envDefault:"log"`

	// From is the envelope sender.
	From string `env:"MAIL_FROM" envDefault:"no-reply@example.com"`

	// BaseURL is the public origin of your FRONT END -- the thing that will receive
	// the links in these emails and hand the token back to this API. It is not the
	// API's own address unless the two are the same.
	BaseURL string `env:"APP_BASE_URL" envDefault:"http://localhost:8080"`

	SMTPHost     string `env:"SMTP_HOST" envDefault:"localhost"`
	SMTPPort     int    `env:"SMTP_PORT" envDefault:"587"`
	SMTPUsername string `env:"SMTP_USERNAME" envDefault:""`
	SMTPPassword string `env:"SMTP_PASSWORD" envDefault:""`
}

// RateLimit configures the limiter on the public endpoints.
//
// It is IN-MEMORY and therefore PER-REPLICA: three replicas means three times the
// configured allowance. That is a deliberate trade -- the alternative is a shared
// counter, which means Redis, which this template does not have.
//
// It is a speed bump, not a wall. A serious deployment puts the real limiter at
// the proxy or the WAF, where it can see every replica's traffic and drop the
// request before it costs you a goroutine. This one exists so that an unprotected
// deployment is not trivially brute-forceable.
type RateLimit struct {
	// Enabled turns the limiter off entirely. Useful in tests.
	Enabled bool `env:"RATE_LIMIT_ENABLED" envDefault:"true"`
	// Attempts is how many requests one key may make per Window.
	Attempts int `env:"RATE_LIMIT_ATTEMPTS" envDefault:"10"`
	// Window is the period over which Attempts are counted.
	Window time.Duration `env:"RATE_LIMIT_WINDOW" envDefault:"1m"`
}

// Audit holds the audit log's retention policy.
type Audit struct {
	// Retention is how long audit entries are kept. ZERO -- THE DEFAULT -- MEANS
	// KEEP FOREVER.
	//
	// The default is deliberate. Quietly destroying somebody's compliance evidence
	// because a config value defaulted to 90 days is not a decision this template
	// will make on your behalf. Set it, once you know what your obligations are:
	// most regimes want years, and "forever" is a real answer too, right up until
	// a right-to-erasure request arrives.
	//
	// The purge is the ONLY thing permitted to delete from audit_log; the database
	// trigger from migration 00009 refuses everything else.
	Retention time.Duration `env:"AUDIT_RETENTION" envDefault:"0"`
}

// Tenant holds the tenant lifecycle policy.
type Tenant struct {
	// Retention is how long a SOFT-DELETED tenant is kept before it is destroyed
	// for real, cascading away every row it owns. ZERO -- THE DEFAULT -- MEANS KEEP
	// FOREVER.
	//
	// This is your right-to-erasure mechanism, and it is the only thing in the
	// application that permanently destroys tenant data. It is off by default for
	// the same reason AUDIT_RETENTION is: silently shredding a customer's data
	// because a config value had a tidy default is not a decision this template
	// makes for you. 30d is a common choice, and gives support time to undo an
	// accident.
	Retention time.Duration `env:"TENANT_RETENTION" envDefault:"0"`
}

// CORS controls which browser origins may call this API.
type CORS struct {
	// AllowedOrigins is an explicit allowlist, e.g.
	// "https://app.example.com,https://admin.example.com".
	//
	// Empty means CORS is OFF and no browser on another origin can call the API,
	// which is the correct default for an API with no browser client.
	//
	// A "*" wildcard is REFUSED at startup in production. The API authenticates
	// with a bearer token, and a wildcard origin that also allows credentials is
	// precisely the configuration the CORS spec forbids -- every site on the
	// internet would be able to make authenticated calls with your users' tokens.
	AllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:","`
}

// App holds top-level, environment-wide options.
type App struct {
	// Environment is one of "development", "staging", "production".
	Environment string `env:"APP_ENV" envDefault:"development"`
	// Debug enables human-readable logs and developer-friendly error output.
	// It must be false in production: it is what decides whether internal error
	// messages are echoed back to the caller.
	Debug bool `env:"APP_DEBUG" envDefault:"true"`
	// LogLevel is one of "debug", "info", "warn", "error".
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// InstanceID uniquely identifies this replica. In Kubernetes this is
	// typically injected from metadata.name via the downward API; it tags every
	// log line so you can tell replicas apart in aggregated logs.
	InstanceID string `env:"INSTANCE_ID" envDefault:""`
}

// Server holds HTTP server configuration.
type Server struct {
	Host            string        `env:"SERVER_HOST" envDefault:"0.0.0.0"`
	Port            int           `env:"SERVER_PORT" envDefault:"8080"`
	ReadTimeout     time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout    time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout     time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	ShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"15s"`
	// TrustProxyHeaders makes the server believe X-Forwarded-For when recording
	// a client IP. Enable it only when the app really does sit behind a proxy
	// or load balancer that overwrites the header, otherwise a caller can forge
	// the IP that lands in your session and audit records.
	TrustProxyHeaders bool `env:"SERVER_TRUST_PROXY_HEADERS" envDefault:"false"`
}

// Addr returns the host:port the HTTP server should bind to.
func (s Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// Postgres holds the connection settings for the database, which is the only
// source of truth in this template: there is no cache tier to invalidate.
type Postgres struct {
	Host string `env:"POSTGRES_HOST" envDefault:"localhost"`
	Port int    `env:"POSTGRES_PORT" envDefault:"5432"`
	// ONE user, owning ONE database -- the app's own. The app never connects as the
	// cluster superuser and never touches another database.
	//
	// Note what this design does NOT give you: a tamper-proof audit log. A user with
	// full rights over the database can delete from audit_log, and the append-only
	// trigger cannot stop it (any role may set the GUC the trigger checks). See the
	// audit package. That was a deliberate trade for operational simplicity.
	User            string        `env:"POSTGRES_USER" envDefault:"app"`
	Password        string        `env:"POSTGRES_PASSWORD" envDefault:"app"`
	Database        string        `env:"POSTGRES_DB" envDefault:"app"`
	SSLMode         string        `env:"POSTGRES_SSLMODE" envDefault:"disable"`
	MaxConns        int32         `env:"POSTGRES_MAX_CONNS" envDefault:"10"`
	MinConns        int32         `env:"POSTGRES_MIN_CONNS" envDefault:"2"`
	MaxConnLifetime time.Duration `env:"POSTGRES_MAX_CONN_LIFETIME" envDefault:"1h"`
	MaxConnIdleTime time.Duration `env:"POSTGRES_MAX_CONN_IDLE_TIME" envDefault:"30m"`
}

// DSN returns a libpq-style connection string.
func (p Postgres) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.Database, p.SSLMode,
	)
}

// Auth holds the knobs for password hashing and session lifetime.
type Auth struct {
	// SessionTTL is how long a session token stays valid after login.
	SessionTTL time.Duration `env:"AUTH_SESSION_TTL" envDefault:"720h"` // 30 days
	// InvitationTTL is how long an emailed invitation link stays valid.
	InvitationTTL time.Duration `env:"AUTH_INVITATION_TTL" envDefault:"168h"` // 7 days
	// PasswordResetTTL is how long a reset link stays valid. Deliberately SHORT:
	// unlike an invitation, a reset link is a credential an attacker may have
	// triggered against somebody else's account, and every hour it stays alive is
	// an hour it can be intercepted.
	PasswordResetTTL time.Duration `env:"AUTH_PASSWORD_RESET_TTL" envDefault:"1h"`
	// EmailVerifyTTL is how long a "confirm your address" link stays valid.
	EmailVerifyTTL time.Duration `env:"AUTH_EMAIL_VERIFY_TTL" envDefault:"24h"`

	// RequireVerifiedEmail gates TENANT CREATION on a confirmed address -- not
	// login. Locking somebody out of their own account because a verification mail
	// went to spam is a support nightmare for very little gain; stopping an
	// unverified address from standing up tenants is the control that matters, and
	// it doubles as abuse prevention.
	//
	// Turn it off if you verify out of band (SSO, an invite-only product).
	RequireVerifiedEmail bool `env:"AUTH_REQUIRE_VERIFIED_EMAIL" envDefault:"true"`

	// MaxTenantsPerUser caps how many live tenants one account may belong to.
	// Without it, a single account can stand up unlimited tenants: free storage for
	// them, an abuse vector for you. 0 means no limit.
	MaxTenantsPerUser int `env:"AUTH_MAX_TENANTS_PER_USER" envDefault:"10"`
	// MinPasswordLength is the only password rule enforced. Length beats
	// composition rules; see OWASP's authentication cheat sheet.
	MinPasswordLength int `env:"AUTH_MIN_PASSWORD_LENGTH" envDefault:"12"`

	// Argon2id parameters. The defaults are OWASP's recommended second option
	// (19 MiB memory, 2 iterations, 1 degree of parallelism). Raise ArgonMemory
	// or ArgonTime if your hardware can afford it -- and never lower them below
	// the OWASP floor to make tests faster; lower them in the test itself.
	ArgonMemoryKiB   uint32 `env:"AUTH_ARGON_MEMORY_KIB" envDefault:"19456"`
	ArgonIterations  uint32 `env:"AUTH_ARGON_ITERATIONS" envDefault:"2"`
	ArgonParallelism uint8  `env:"AUTH_ARGON_PARALLELISM" envDefault:"1"`
}

// Load reads the .env file (if present) and parses environment variables into
// a Settings value. A missing .env file is not an error -- in production the
// configuration comes from real environment variables, ConfigMaps, and Secrets.
func Load() (*Settings, error) {
	// Best-effort: load .env if it exists. Real environment variables always win,
	// because godotenv does not overwrite variables that are already set.
	_ = godotenv.Load()

	var s Settings
	if err := env.Parse(&s); err != nil {
		return nil, fmt.Errorf("settings: parse environment: %w", err)
	}

	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// IsProduction reports whether the app is running in a production environment.
func (s *Settings) IsProduction() bool {
	return s.App.Environment == "production"
}

// validate rejects configurations that would be unsafe or nonsensical, at
// startup, rather than letting them fail later under load.
func (s *Settings) validate() error {
	if s.Server.Port <= 0 || s.Server.Port > 65535 {
		return fmt.Errorf("settings: invalid SERVER_PORT %d", s.Server.Port)
	}
	if s.Postgres.MinConns > s.Postgres.MaxConns {
		return fmt.Errorf(
			"settings: POSTGRES_MIN_CONNS (%d) exceeds POSTGRES_MAX_CONNS (%d)",
			s.Postgres.MinConns, s.Postgres.MaxConns,
		)
	}
	// A zero TTL is not "no expiry" -- it makes expires_at equal now(), so every
	// token is expired the instant it is minted, and the user gets a link that
	// silently never works. Refuse all three rather than ship that.
	if s.Auth.SessionTTL <= 0 {
		return fmt.Errorf("settings: AUTH_SESSION_TTL must be positive")
	}
	if s.Auth.InvitationTTL <= 0 {
		return fmt.Errorf("settings: AUTH_INVITATION_TTL must be positive (a zero TTL mints links that are already expired)")
	}
	if s.Auth.PasswordResetTTL <= 0 {
		return fmt.Errorf("settings: AUTH_PASSWORD_RESET_TTL must be positive (a zero TTL mints links that are already expired)")
	}
	if s.Auth.MinPasswordLength < 8 {
		return fmt.Errorf("settings: AUTH_MIN_PASSWORD_LENGTH must be at least 8")
	}
	if s.Auth.ArgonParallelism == 0 {
		return fmt.Errorf("settings: AUTH_ARGON_PARALLELISM must be at least 1")
	}
	// Debug mode leaks internal error strings to callers, so it must never be on
	// in production even if someone sets it there by accident.
	if s.IsProduction() && s.App.Debug {
		return fmt.Errorf("settings: APP_DEBUG must be false when APP_ENV=production")
	}
	if s.IsProduction() && s.Postgres.SSLMode == "disable" {
		return fmt.Errorf("settings: POSTGRES_SSLMODE must not be 'disable' in production")
	}

	switch s.Mail.Backend {
	case "log", "smtp":
	default:
		return fmt.Errorf("settings: unknown MAIL_BACKEND %q (want log|smtp)", s.Mail.Backend)
	}

	// The log mailer prints the entire email -- including the invitation and
	// password-reset LINKS, which are working credentials. In production that means
	// putting credentials into your log aggregator, where they are retained,
	// indexed, and visible to everyone with log access. Refuse.
	if s.IsProduction() && s.Mail.Backend == "log" {
		return fmt.Errorf("settings: MAIL_BACKEND=log writes invitation and password-reset links to the log; set MAIL_BACKEND=smtp when APP_ENV=production")
	}

	// A password-reset link that points at localhost is a password reset nobody can
	// complete.
	if s.IsProduction() && strings.Contains(s.Mail.BaseURL, "localhost") {
		return fmt.Errorf("settings: APP_BASE_URL is still %q in production; the links in your emails would point at localhost", s.Mail.BaseURL)
	}

	if s.Auth.EmailVerifyTTL <= 0 {
		return fmt.Errorf("settings: AUTH_EMAIL_VERIFY_TTL must be positive (a zero TTL mints links that are already expired)")
	}

	// A wildcard origin plus bearer-token auth is the exact configuration the CORS
	// spec forbids: it would let every site on the internet make authenticated
	// calls with your users' tokens.
	for _, origin := range s.CORS.AllowedOrigins {
		if origin == "*" && s.IsProduction() {
			return fmt.Errorf("settings: CORS_ALLOWED_ORIGINS must not contain '*' in production -- this API authenticates with bearer tokens, and a wildcard origin would expose them to every site on the internet")
		}
	}

	if s.RateLimit.Enabled && (s.RateLimit.Attempts <= 0 || s.RateLimit.Window <= 0) {
		return fmt.Errorf("settings: RATE_LIMIT_ATTEMPTS and RATE_LIMIT_WINDOW must be positive when the limiter is enabled")
	}

	return nil
}
