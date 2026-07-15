// Command server is the application entrypoint.
//
// Modes, chosen by the first argument:
//
//	server                            start the HTTP API
//	server migrate up|down|...        apply the embedded migrations, then exit
//	server grant-superuser <email>    grant the global superuser flag
//	server revoke-superuser <email>   take it away
//
// The migrate mode is why the same image can be both the app and its own
// migrator: docker-compose runs it as a one-shot job the app waits on, and
// Kubernetes runs the identical container as an init container or Job.
//
// grant-superuser lives here, rather than behind an HTTP route, so that the most
// powerful privilege in the system takes database access to obtain -- not merely
// a stolen bearer token.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/identity"
	"github.com/miguelrosalesmtl/go-template/internal/logger"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
	"github.com/miguelrosalesmtl/go-template/internal/server"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// sessionCleanup controls the background pruning of dead session rows. Sessions
// are the only table here that grows without bound, so something has to sweep it.
const (
	cleanupInterval = 1 * time.Hour
	// Keep expired and revoked sessions around for a while before deleting them,
	// so they remain visible to an incident investigation.
	sessionRetention = 720 * time.Hour // 30 days
)

func main() {
	var err error

	subcommand := ""
	if len(os.Args) > 1 {
		subcommand = os.Args[1]
	}

	switch subcommand {
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "grant-superuser":
		err = runSetSuperuser(os.Args[2:], true)
	case "revoke-superuser":
		err = runSetSuperuser(os.Args[2:], false)
	case "purge":
		err = runPurge()
	case "":
		err = run()
	default:
		_, _ = os.Stderr.WriteString("unknown subcommand " + subcommand + "\n" + usage)
		os.Exit(2)
	}

	if err != nil {
		// The logger may not exist yet if settings failed, so fall back to stderr.
		_, _ = os.Stderr.WriteString("fatal: " + err.Error() + "\n")
		os.Exit(1)
	}
}

const usage = `usage:
  server                            start the HTTP API
  server migrate [up|down|status|reset]
  server grant-superuser <email>    make a user a global superuser
  server revoke-superuser <email>   take it away
  server purge                      DESTROY data past its retention (privileged)
`

// runSetSuperuser handles `server grant-superuser <email>` and its inverse.
//
// The superuser flag is granted HERE and nowhere else -- there is no HTTP route
// that can set it. Acquiring the most powerful privilege in the system therefore
// requires access to the database credentials, not merely a stolen bearer token,
// and a compromised superuser account cannot mint more of itself.
func runSetSuperuser(args []string, grant bool) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("expected exactly one argument: an email address")
	}
	email := args[0]

	cfg, err := settings.Load()
	if err != nil {
		return err
	}
	log := logger.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()

	// The CLI sends no email, so a log mailer is the right thing here regardless of
	// what MAIL_BACKEND says.
	svc := identity.NewService(pool, cfg.Auth, cfg.Mail, mail.NewLogMailer(log), log)

	user, err := svc.SetSuperuser(ctx, email, grant)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return fmt.Errorf("no user with email %q -- they must register first", email)
		}
		return err
	}

	verb := "revoked superuser from"
	if grant {
		verb = "granted superuser to"
	}
	fmt.Printf("%s %s (%s)\n", verb, user.Email, user.ID)
	return nil
}

// runMigrate handles the `migrate` subcommand. Direction defaults to "up".
func runMigrate(args []string) error {
	direction := "up"
	if len(args) > 0 {
		direction = args[0]
	}

	cfg, err := settings.Load()
	if err != nil {
		return err
	}
	return database.Migrate(cfg.Postgres, direction, logger.New(cfg))
}

func run() error {
	cfg, err := settings.Load()
	if err != nil {
		return err
	}

	log := logger.New(cfg)
	log.Info("starting", slog.String("environment", cfg.App.Environment))

	// Root context, cancelled on SIGINT/SIGTERM -- the latter is what Kubernetes
	// and `docker compose down` send. Everything below hangs off it, so a signal
	// unwinds the whole process in order.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to postgres",
		slog.String("host", cfg.Postgres.Host),
		slog.String("database", cfg.Postgres.Database),
	)

	mailer := newMailer(cfg, log)
	identityService := identity.NewService(pool, cfg.Auth, cfg.Mail, mailer, log)

	// Reconcile the permission catalog in the database with the one compiled into
	// this binary. Permissions come from code; roles are data. Adding a permission
	// is therefore a code change plus a restart, not a migration.
	//
	// This fails startup if it cannot run: a process whose catalog disagrees with
	// its own enforcement points would let a role editor offer permissions that
	// nothing checks, which is precisely the failure the design exists to prevent.
	if err := identityService.SyncPermissions(ctx); err != nil {
		return err
	}

	go reap(ctx, identityService, log)

	srv := server.New(cfg.Server, cfg.RateLimit, cfg.CORS, cfg.App.Debug, identityService, pool, log)

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Start() }()

	// Block until the server dies on its own or a shutdown signal arrives.
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	// Drain in-flight requests, but not forever. The deadline hangs off
	// context.Background(), not ctx -- ctx is already cancelled, and a shutdown
	// context derived from it would expire instantly and drop every live request.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", slog.String("error", err.Error()))
		return err
	}
	log.Info("shutdown complete")
	return nil
}

// newMailer builds the Mailer named by MAIL_BACKEND.
//
// The "log" backend prints the whole email -- invitation and reset LINKS included --
// to the application log. That is what makes the template runnable with no setup,
// and it is why settings.validate refuses it when APP_ENV=production: those links
// are working credentials, and this would put them in your log aggregator.
func newMailer(cfg *settings.Settings, log *slog.Logger) mail.Mailer {
	if cfg.Mail.Backend == "smtp" {
		log.Info("sending mail over SMTP", slog.String("host", cfg.Mail.SMTPHost))
		return mail.NewSMTPMailer(
			cfg.Mail.SMTPHost, cfg.Mail.SMTPPort,
			cfg.Mail.SMTPUsername, cfg.Mail.SMTPPassword,
			cfg.Mail.From,
		)
	}

	log.Warn("MAIL_BACKEND=log: emails are PRINTED TO THIS LOG, not sent. " +
		"Invitation and password-reset links will appear here in full.")
	return mail.NewLogMailer(log)
}

// reap prunes the short-lived credential tables: sessions, password resets, and
// email verifications. All three grow without bound and nothing else would ever
// remove them.
//
// Every replica runs this. That is harmless -- the DELETEs are idempotent and the
// duplicated work is a couple of indexed statements an hour -- and it means the
// cleanup needs no leader election and no separate cron deployment.
//
// It does NOT purge the audit log or destroy soft-deleted organizations. That is `server
// purge`, a separate command you schedule yourself, because destroying history
// should be a deliberate act rather than something a long-running process does on
// a ticker.
//
// Note what is NOT enforcing that separation: database privileges. This template
// runs a SINGLE user that owns the database, so the app holds DELETE on every table
// in it, audit_log included -- the append-only trigger guards against mistakes, not
// against code already running as the app. Keeping destruction out of the app is a
// discipline here, not a guarantee. See internal/audit/audit.go for the two-identity
// design that would make it one.
func reap(ctx context.Context, svc *identity.Service, log *slog.Logger) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			deleted, err := svc.CleanupSessions(ctx, sessionRetention)
			if err != nil {
				// Not fatal: the app serves fine with a few stale rows, and the next
				// tick will try again.
				log.Warn("session cleanup failed", slog.String("error", err.Error()))
			} else if deleted > 0 {
				log.Info("pruned dead sessions", slog.Int64("count", deleted))
			}

			// Spent and expired password-reset tokens. Same reasoning as sessions:
			// nothing else would ever remove them.
			if purged, err := svc.CleanupPasswordResets(ctx, sessionRetention); err != nil {
				log.Warn("password-reset cleanup failed", slog.String("error", err.Error()))
			} else if purged > 0 {
				log.Info("pruned dead password resets", slog.Int64("count", purged))
			}

			// Spent and expired email-verification tokens.
			if purged, err := svc.CleanupEmailVerifications(ctx, sessionRetention); err != nil {
				log.Warn("email-verification cleanup failed", slog.String("error", err.Error()))
			} else if purged > 0 {
				log.Info("pruned dead email verifications", slog.Int64("count", purged))
			}

		}
	}
}

// runPurge handles `server purge`. It DESTROYS DATA, permanently.
//
// It is a separate command rather than something the running app does on a ticker,
// because destroying an audit trail should be a deliberate act -- exactly like a
// migration. Run it as a cron job or a Kubernetes CronJob, with the same connection
// settings the `migrate` job uses:
//
//	server purge
//
// BE CLEAR ABOUT WHAT SEPARATES IT, THOUGH: not database privileges. This template
// runs a single user that owns the database, so the app connects as `app` and holds
// DELETE on audit_log just as this command does -- code running as the app could do
// everything below if it were compromised into trying (see the append-only trigger
// in migration 00009, which guards against mistakes, not against an adversary).
// Splitting into a privileged identity for this command and a restricted one for the
// app is the change that would turn this convention into an actual boundary.
//
// It honours AUDIT_RETENTION and ORGANIZATION_RETENTION, both of which default to 0 --
// "keep forever" -- so with no configuration this command does nothing at all.
func runPurge() error {
	cfg, err := settings.Load()
	if err != nil {
		return err
	}
	log := logger.New(cfg)

	if cfg.Audit.Retention <= 0 && cfg.Organization.Retention <= 0 {
		log.Info("nothing to purge: both AUDIT_RETENTION and ORGANIZATION_RETENTION are 0 (keep forever)")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := database.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()

	svc := identity.NewService(pool, cfg.Auth, cfg.Mail, mail.NewLogMailer(log), log)

	// Organizations first: the cascade takes their audit entries with it, so purging them
	// before the audit sweep saves the sweep the work.
	if cfg.Organization.Retention > 0 {
		n, err := svc.PurgeDeletedOrganizations(ctx, cfg.Organization.Retention)
		if err != nil {
			return fmt.Errorf("purge organizations: %w", err)
		}
		log.Warn("PERMANENTLY DESTROYED soft-deleted organizations and every row they owned",
			slog.Int64("organizations", n),
			slog.Duration("retention", cfg.Organization.Retention),
		)
	}

	if cfg.Audit.Retention > 0 {
		var n int64
		err := database.InTx(ctx, pool, func(db database.DB) error {
			var err error
			n, err = audit.NewRecorder(db).Purge(ctx, cfg.Audit.Retention)
			return err
		})
		if err != nil {
			return fmt.Errorf("purge audit log: %w", err)
		}
		log.Warn("PERMANENTLY DESTROYED audit entries",
			slog.Int64("entries", n),
			slog.Duration("retention", cfg.Audit.Retention),
		)
	}
	return nil
}
