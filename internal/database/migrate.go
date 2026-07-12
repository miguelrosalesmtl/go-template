package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	// pgx's database/sql driver, required because goose is built on database/sql
	// rather than on pgx's native interface.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
	"github.com/miguelrosalesmtl/go-template/migrations"
)

// Migrate runs the embedded goose migrations against Postgres. direction is one
// of "up", "down" (one step), "status", or "reset" (roll everything back).
//
// The .sql files are compiled into the binary (see migrations/embed.go), so the
// same image is both the application and its own migrator: docker-compose runs
// it as a one-shot `migrate up` job that the app waits on, and Kubernetes runs
// the identical container as an init container or Job.
//
// It opens its own short-lived database/sql connection rather than reusing the
// app's pgxpool, because goose cannot speak to a pgxpool.
func Migrate(cfg settings.Postgres, direction string, log *slog.Logger) error {
	db, err := sql.Open("pgx", cfg.DSN())
	if err != nil {
		return fmt.Errorf("database: open migration connection: %w", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("database: ping for migration: %w", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("database: set goose dialect: %w", err)
	}

	log.Info("running migrations", slog.String("direction", direction))

	// "." is the root of the embedded FS, not the working directory.
	switch direction {
	case "up":
		return goose.Up(db, ".")
	case "down":
		return goose.Down(db, ".")
	case "status":
		return goose.Status(db, ".")
	case "reset":
		return goose.Reset(db, ".")
	default:
		return fmt.Errorf("database: unknown migrate direction %q (want up|down|status|reset)", direction)
	}
}
