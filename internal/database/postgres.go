// Package database owns the Postgres connection pool and the migration runner.
//
// Postgres is the only source of truth in this template. There is no cache tier,
// so there is nothing to invalidate and no second system to keep consistent.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// DB is the subset of pgx used by repositories. Both *pgxpool.Pool and pgx.Tx
// satisfy it, which is what lets a repository method run either standalone or
// inside a caller's transaction without knowing the difference.
//
// Repositories should depend on this interface, never on *pgxpool.Pool directly.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Compile-time proof that the two implementations we care about satisfy DB.
var (
	_ DB = (*pgxpool.Pool)(nil)
	_ DB = (pgx.Tx)(nil)
)

// NewPool builds and verifies a pgx connection pool from settings. The pool is
// safe for concurrent use and is shared across the process.
func NewPool(ctx context.Context, cfg settings.Postgres) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("database: parse config: %w", err)
	}

	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("database: create pool: %w", err)
	}

	// ParseConfig + NewWithConfig do not talk to the server, so without this the
	// process would start "successfully" against an unreachable database.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return pool, nil
}

// InTx runs fn inside a transaction, committing if it returns nil and rolling
// back otherwise. The DB handed to fn is the transaction, so any repository
// method called with it joins the same atomic unit.
//
// Use it whenever one logical operation writes more than one table -- accepting
// an invitation, for example, creates a membership and marks the invitation
// accepted, and must not be able to do only one of those.
func InTx(ctx context.Context, pool *pgxpool.Pool, fn func(DB) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	// Rollback after a successful Commit is a no-op that returns ErrTxClosed, so
	// this defer is safe on every path and guarantees we never leak a connection
	// holding an open transaction, even on panic.
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit transaction: %w", err)
	}
	return nil
}
