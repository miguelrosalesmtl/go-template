package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// The audit log's two hard promises: nobody can rewrite it, and it records the
// refusals as well as the successes.

// What the append-only trigger actually guarantees -- and, just as importantly,
// what it does not.
//
// It stops MISTAKES: a careless query, a bad migration, an injected DELETE. Those
// are worth stopping and this proves it does.
//
// It does NOT stop an adversary who already controls the application process. See
// TestTheAppCanBypassTheAuditTriggerIfItWantsTo, immediately below, which pins that
// down deliberately -- because a limit you have not written a test for is a limit
// somebody will discover at the worst possible moment.
func TestAuditLogRefusesAccidentalTampering(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Produce one entry to attack.
	acme, alice := setupTenantWithOwner(t, svc)
	_ = alice

	entries, err := audit.NewRecorder(testPool).List(ctx, acme.ID, audit.Filter{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("creating a tenant wrote no audit entry")
	}
	victim := entries[0]

	// A plain UPDATE or DELETE -- the shape a bug or an injected statement takes --
	// is refused outright.
	t.Run("UPDATE is refused", func(t *testing.T) {
		_, err := testPool.Exec(ctx,
			`UPDATE audit_log SET action = 'nothing.happened' WHERE id = $1`, victim.ID)
		if err == nil {
			t.Fatal("an audit entry was successfully rewritten: the log is not append-only")
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Errorf("refused, but not by the append-only trigger: %v", err)
		}
	})

	t.Run("DELETE is refused", func(t *testing.T) {
		_, err := testPool.Exec(ctx, `DELETE FROM audit_log WHERE id = $1`, victim.ID)
		if err == nil {
			t.Fatal("an audit entry was successfully deleted: the log is not append-only")
		}
		if !strings.Contains(err.Error(), "append-only") {
			t.Errorf("refused, but not by the append-only trigger: %v", err)
		}
	})

	t.Run("the entry is untouched", func(t *testing.T) {
		after, err := audit.NewRecorder(testPool).List(ctx, acme.ID, audit.Filter{})
		if err != nil {
			t.Fatalf("list audit: %v", err)
		}
		if len(after) != len(entries) {
			t.Fatalf("the log has %d entries, had %d", len(after), len(entries))
		}
		if after[0].Action != victim.Action {
			t.Errorf("the action was changed to %q", after[0].Action)
		}
	})

	// The one exception, and it has to announce itself: the retention sweep sets
	// app.audit_purge, and only then may it delete.
	t.Run("the retention sweep is the one permitted exception", func(t *testing.T) {
		var purged int64
		err := database.InTx(ctx, testPool, func(db database.DB) error {
			var err error
			// Retain nothing: purge everything, so we can see it work at all.
			purged, err = audit.NewRecorder(db).Purge(ctx, 1*time.Nanosecond)
			return err
		})
		if err != nil {
			t.Fatalf("the retention sweep could not purge: %v", err)
		}
		if purged == 0 {
			t.Error("the sweep deleted nothing; it should have removed the expired entries")
		}
	})

	t.Run("a zero retention keeps everything forever", func(t *testing.T) {
		// The default. Destroying compliance evidence because a config value had a
		// tidy default is not a decision this template makes for anybody.
		var purged int64
		err := database.InTx(ctx, testPool, func(db database.DB) error {
			var err error
			purged, err = audit.NewRecorder(db).Purge(ctx, 0)
			return err
		})
		if err != nil {
			t.Fatalf("purge with zero retention: %v", err)
		}
		if purged != 0 {
			t.Errorf("a zero retention deleted %d entries; it must delete none", purged)
		}
	})
}

// Successes alone make a change-history. It is the DENIALS that make it a security
// trail: without them, somebody working through a password list produces no record
// at all, and an empty audit log reads exactly like "nothing happened".
func TestFailedLoginsAreAudited(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice@example.com", goodPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Three different failures. The CALLER cannot tell them apart -- that is what
	// stops login from being an account-enumeration oracle -- but the audit log
	// records exactly which, because you need to tell a typo from an attack.
	if _, _, err := svc.Login(ctx, "alice@example.com", "wrong-password", RequestMeta{}); err == nil {
		t.Fatal("a wrong password logged in")
	}
	if _, _, err := svc.Login(ctx, "nobody@example.com", goodPassword, RequestMeta{}); err == nil {
		t.Fatal("an unknown email logged in")
	}

	root := makeSuperuser(t, svc, "root@example.com")
	if _, err := svc.SetUserActive(ctx, root, alice.ID, false); err != nil {
		t.Fatalf("deactivate alice: %v", err)
	}
	if _, _, err := svc.Login(ctx, "alice@example.com", goodPassword, RequestMeta{}); err == nil {
		t.Fatal("a deactivated user logged in")
	}

	// Failed logins have no tenant -- there is none yet -- so they are read straight
	// from the table rather than through the tenant-scoped List.
	rows, err := testPool.Query(ctx,
		`SELECT metadata->>'reason', metadata->>'email'
		 FROM audit_log WHERE action = $1 ORDER BY id`, audit.ActionLoginFailed)
	if err != nil {
		t.Fatalf("query failed logins: %v", err)
	}
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var reason, email string
		if err := rows.Scan(&reason, &email); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[reason] = email
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}

	for reason, wantEmail := range map[string]string{
		"wrong_password": "alice@example.com",
		"unknown_email":  "nobody@example.com",
		"deactivated":    "alice@example.com",
	} {
		if got[reason] != wantEmail {
			t.Errorf("no audit entry for a %s failure against %q (got %q)", reason, wantEmail, got[reason])
		}
	}
}

func TestAuditSearch(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	acme, alice := setupTenantWithOwner(t, svc)
	aAccess := accessFor(t, svc, alice, acme.Slug)

	if _, err := svc.CreateRole(ctx, alice, aAccess, "auditor", "Auditor",
		[]Permission{PermAuditRead}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := svc.UpdateTenant(ctx, alice, aAccess, "Acme Corp"); err != nil {
		t.Fatalf("rename tenant: %v", err)
	}

	rec := audit.NewRecorder(testPool)

	t.Run("filter by action", func(t *testing.T) {
		entries, err := rec.List(ctx, acme.ID, audit.Filter{Action: audit.ActionRoleCreated})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("got %d entries for roles.created, want 1", len(entries))
		}
		if entries[0].Action != audit.ActionRoleCreated {
			t.Errorf("the filter returned a %q entry", entries[0].Action)
		}
	})

	t.Run("filter by actor", func(t *testing.T) {
		entries, err := rec.List(ctx, acme.ID, audit.Filter{ActorUserID: &alice.ID})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("alice did several things; the actor filter found none of them")
		}
		for _, e := range entries {
			if e.ActorUserID == nil || *e.ActorUserID != alice.ID {
				t.Fatal("the actor filter returned somebody else's entry")
			}
		}
	})

	t.Run("filter by time window", func(t *testing.T) {
		// A window in the past: everything just happened, so nothing should match.
		entries, err := rec.List(ctx, acme.ID, audit.Filter{
			From: time.Now().Add(-2 * time.Hour),
			To:   time.Now().Add(-1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("a window ending an hour ago matched %d of today's entries", len(entries))
		}

		// A window that contains now.
		entries, err = rec.List(ctx, acme.ID, audit.Filter{From: time.Now().Add(-1 * time.Hour)})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) == 0 {
			t.Error("a window containing the last hour matched nothing")
		}
	})

	t.Run("an unknown action matches nothing rather than everything", func(t *testing.T) {
		// The failure mode worth guarding: a filter that silently does not apply.
		entries, err := rec.List(ctx, acme.ID, audit.Filter{Action: "no.such.action"})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("an unknown action matched %d entries; the filter is being ignored", len(entries))
		}
	})
}

// THE LIMIT OF THE GUARANTEE, WRITTEN DOWN ON PURPOSE.
//
// This template runs a SINGLE database user that owns the database -- one secret,
// one connection string, deliberately chosen for operational simplicity. The
// consequence is that the append-only trigger cannot stop that user: the DELETE
// branch permits anything that sets the app.audit_purge GUC, and ANY role can set
// it. No special privilege is needed.
//
// So an attacker who is already executing code as the application can erase the
// audit log. This test asserts that, rather than pretending otherwise, because an
// undocumented limit is one somebody finds out about during an incident.
//
// If you need the audit log to survive a compromised app, the change is: a second,
// restricted database identity for the runtime, holding no DELETE on audit_log,
// with the privileged identity used only by migrations and `server purge`. The
// trigger is not what would be doing the work -- the GRANT would.
func TestTheAppCanBypassTheAuditTriggerIfItWantsTo(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	setupTenantWithOwner(t, svc) // produces audit entries

	var before int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&before); err != nil {
		t.Fatalf("count: %v", err)
	}
	if before == 0 {
		t.Fatal("no audit entries to work with")
	}

	// Exactly what a compromised app could run. It is not clever, and it works.
	err := database.InTx(ctx, testPool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		_, err := db.Exec(ctx, `DELETE FROM audit_log`)
		return err
	})
	if err != nil {
		t.Fatalf("the bypass failed -- which would mean this template's guarantee is "+
			"STRONGER than documented. Good news, but the docs and this test are now "+
			"wrong and must be updated: %v", err)
	}

	var after int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&after); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != 0 {
		t.Fatalf("expected the bypass to erase the log (%d rows before); %d remain", before, after)
	}

	// Recorded here so it can never be a surprise:
	t.Log("CONFIRMED: the single database user CAN erase the audit log by setting " +
		"app.audit_purge. The trigger guards against mistakes, not against an attacker " +
		"who controls the application. See migrations/00009 and the README.")
}
