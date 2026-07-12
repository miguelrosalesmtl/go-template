# Multi-tenant project template

A Go starting point for multi-tenant SaaS backends. Users, tenants, memberships,
roles, sessions, invitations, and an audit log — all working, all tested — plus
the Postgres, Docker, and configuration plumbing you would otherwise rewrite for
the fifth time.

There is no Redis and no cache tier. Postgres is the only source of truth, so
there is nothing to invalidate and no second system to keep consistent.

## Start a project with it

```sh
cp -r multi-tenant-project-template my-project && cd my-project
make rename m=github.com/you/my-project   # rewrite the module path everywhere
make env                                  # .env from .env.example
make up                                   # Postgres + migrations + app on :8080
```

Then delete this README and write your own.

If 5432 or 8080 is already taken by another project's stack, edit the `ports:`
lines in `docker-compose.yml` — only the host side needs to move, since inside
the compose network Postgres is always 5432 and the app always 8080.

## What you get

| Concern | Where | Notes |
| --- | --- | --- |
| Config | `internal/settings` | One typed struct from env vars. Nothing else reads `os.Getenv`. |
| Database | `internal/database` | pgx pool, embedded goose migrations, `InTx` helper. |
| Passwords & tokens | `internal/auth` | argon2id hashing; opaque bearer tokens stored as SHA-256. |
| Identity | `internal/identity` | Users, tenants, memberships, sessions, invitations. |
| **RBAC** | `internal/identity` | `permissions.go` (the code-owned catalog), `roles_service.go` (the escalation guard). |
| Audit | `internal/audit` | Append-only (enforced by a DB trigger), records denials, searchable, keyset-paginated. |
| HTTP | `internal/server` | chi router, auth + tenant + permission middleware, handlers. |

## The tenancy model

A **user** is global — one account, one password, many tenants. A **tenant** is
an isolated account. A **membership** links the two and carries **roles**.

Tenancy is carried in the URL: every tenant-scoped route lives under
`/api/v1/tenants/{tenant}/…`, where `{tenant}` is the slug.

## RBAC

**Permissions come from code. Roles are data.**

That split is the load-bearing idea, so it's worth being precise about it. A
permission like `members.invite` means something *only because* a route is
guarded with `requirePermission(PermMembersInvite)`. If a tenant admin could
invent a permission name at runtime, they'd create `billing.refund`, assign it to
a role, and see it rendered with a checkbox — while it enforced **nothing**. It
would look like it worked and grant zero.

So the **catalog** lives in `internal/identity/permissions.go`, one entry per
enforcement point, served read-only at `GET /api/v1/permissions` for your role
editor to render. A `permissions` table mirrors it, and `role_permissions` has a
**foreign key** into that table — so the database itself refuses to store a grant
for a permission no code checks. What's configurable is **which permissions a
role bundles**.

```
permissions       tenant.read  tenant.update  tenant.delete
                  members.read  members.update  members.delete
                  invitations.read  invitations.create  invitations.delete
                  roles.read  roles.create  roles.update  roles.delete
                  audit.read
                  ↑ from the Go Catalog. Not user-authored.

roles             tenant_id NULL → system role (owner/admin/member), immutable
                  tenant_id set  → a custom role this tenant built
role_permissions  which permissions a role grants   ← THE CONFIGURABLE PART
membership_roles  which roles a member holds        ← many; permissions are the union
```

The naming is `<resource>.<action>` with CRUD verbs, and it has **no exceptions**.
Add a queue, add `queues.create/read/update/delete` — a developer never invents a
verb, and a customer building a role never guesses what a word like "manage" covers.

Two absences are deliberate. There is no **`tenant.create`** and no
**`users.create`**: every permission here is evaluated *inside* a tenant
(`requirePermission` runs after `requireTenant`, against the roles you hold
there), but creating a tenant — or registering — happens when you're not in one
yet. There's nothing to hold a permission against. Those routes are guarded by
authentication alone.

**Roles are per-tenant.** The same person can be an `owner` of one tenant and a
plain `member` of another. There is no "an admin" in the abstract — only an admin
*of a tenant*.

**A member may hold several roles**, and their permissions are the **union**.
That's what lets you give a member billing powers without cloning `member` into a
`member_who_also_does_billing` role — the combinatorial explosion that one-role
systems produce.

| | Scope | |
| --- | --- | --- |
| `owner` | one tenant | Every permission. A tenant always has ≥1; the last cannot be removed or stripped. |
| `admin` | one tenant | **The tenant admin.** Everything except `tenant.delete` — so an admin *can* rename the tenant, but cannot destroy it. |
| `member` | one tenant | `tenant.read`, `members.read`. |
| *custom* | one tenant | Whatever the tenant composes, e.g. "Billing Manager". |
| `is_superuser` | **global** | Not a role — a flag on the user. See below. |

The three system roles are **immutable**, even to an owner. Otherwise a tenant
could strip every permission from `owner` and lock itself out permanently, with
no way back short of a database console.

### The escalation guard

A role editor is, by construction, a machine for handing out permissions. Give an
admin `roles.manage` with no guard and they'll simply build a role holding
`tenant.delete`, assign it to themselves, and walk straight out through every
limit you placed on them. RBAC would be decoration.

One rule prevents it:

> **You may only grant permissions you yourself hold.**

`checkEscalation` in `internal/identity/roles_service.go` enforces it on *every*
path a permission can travel: creating a role, editing a role, deleting a role,
assigning roles to a member, and issuing an invitation (which carries a role).

The elegance is that "only an owner may create an owner" then falls out **for
free** — the `owner` role carries `tenant.delete`, which an admin doesn't hold,
so an admin assigning it fails with no special-casing for owners anywhere.

Two rules can't be expressed as permissions and live alongside it: an admin may
not demote or remove an **owner** (they'd be neutering someone strictly more
powerful, while granting nothing), and the **last owner** can't be removed or
stripped. Both are checked in the service, where the data is.

### Adding a permission

1. Add the constant and a `Catalog` entry in `internal/identity/permissions.go`.
2. Guard a route with `requirePermission(PermYourThing)` in `server.go`.
3. Restart. `SyncPermissions` upserts the catalog at startup — no migration.

Forget step 1 and the FK makes it impossible to grant, so the route becomes
unreachable by anyone but a superuser. That's a loud failure, by design.

### The superuser

`is_superuser` is the only global privilege — the operator of the installation,
not of any one tenant. It grants two things:

1. **The staff surface** at `/api/v1/admin`: list every tenant and user,
   deactivate an account. A non-superuser gets **404** there, not 403 — the
   staff surface does not advertise its own existence.
2. **Entry into any tenant** without a membership, holding every permission in
   the catalog. This is what makes support and debugging possible. They hold no
   *role*, though — they aren't a member of anything; they don't outrank the
   roles, they outrank the question.

The bypass is powerful, so it is never silent. Every entry into a tenant the
superuser does not belong to writes a **`superuser.tenant_accessed`** entry to
that tenant's audit log, with the method and path. **If the audit write fails,
the request fails** — the bypass is permitted precisely because it cannot happen
unobserved, so an unauditable access must not proceed. If you alert on exactly
one thing in this codebase, alert on that action.

A superuser who genuinely *is* a member of a tenant gets their real role and no
flag: auditing their ordinary work in their own tenant would bury the accesses
that matter. Responses carry `via_superuser: true` on a bypass, so a UI can show
a conspicuous "you are here as an operator, not a member" banner.

**Superuser cannot be granted over HTTP.** There is no route for it, by design —
if there were, one stolen superuser token could mint permanent backdoor accounts.
It requires the CLI, and therefore database access:

```sh
server grant-superuser alice@example.com
server revoke-superuser alice@example.com
# in compose:  docker compose exec app /app/server grant-superuser you@example.com
```

Deactivating a user (`PATCH /api/v1/admin/users/{id}` with `{"is_active": false}`)
revokes all their sessions in the same transaction, so the lockout lands on their
very next request rather than whenever their 30-day token happens to expire.

## The tenant lifecycle

`PATCH /tenants/{t}` changes the **name**. The **slug is immutable** — it lives in
every URL, bookmark, saved API call, and webhook config your customers have, and
silently changing it would break all of them. A body containing `slug` is a 400.
A slug is an identifier; the name is the label, and the label is what people
actually want to fix.

`DELETE /tenants/{t}` is a **soft delete**, and it is *total*: the tenant 404s for
everyone at once — **including the owner who just deleted it** — and disappears
from their tenant list. Every query in the repository filters `deleted_at IS NULL`,
which is a footgun of exactly the same class as tenant scoping, and is flagged as
such in the code.

Nothing is destroyed. Every membership, role, invitation, and audit entry stays put,
so a **superuser can restore it whole** — which they have to be able to do, because
a deleted tenant 404s for its own owners, so nobody inside it can ask for it back.

**Deleting releases the slug.** The unique index covers live tenants only, so
someone else can claim `acme` the moment you delete it. That's the one thing a
restore can't always undo: if the slug has been taken, `POST /admin/tenants/{id}/restore`
returns 409 and the superuser must supply a new one. Restore is always possible;
it cannot always give you your old URL back.

> **Not implemented: a purge job.** Soft-deleted tenants live in the database
> forever. That's a deliberate choice, and it's a real GDPR/right-to-erasure gap —
> see the production checklist.

## The audit log

Not a change-history — a security trail. Four properties, in order of how much
they matter:

**It records denials, not just successes.** Failed logins (with *why*: wrong
password vs. unknown email vs. deactivated — indistinguishable to the caller, but
recorded), permission denials, escalation attempts, and rejected invitation tokens.
Without these, someone working through a password list or systematically probing
which permissions they hold produces **no record at all** — and an empty audit log
reads exactly like "nothing happened".

Denials are written in the HTTP **error handler**, not the service, and that's
load-bearing: a refusal aborts its transaction, so an audit entry written *inside*
that transaction would be rolled back along with the very failure it was recording.

**It resists accidents — and be clear that's all.** A database trigger refuses
`UPDATE`, `DELETE`, and `TRUNCATE` on `audit_log`. That catches a careless query, a
bad migration, and an injected `DELETE FROM audit_log`. All worth catching.

**It does NOT make the log tamper-proof against a compromised app**, and the code
says so rather than implying otherwise. The trigger permits a `DELETE` to anything
that sets the `app.audit_purge` GUC — and *any* role can set that GUC, no privilege
required. So code already running as the application can do this:

```sql
BEGIN;
SET LOCAL app.audit_purge = 'on';
DELETE FROM audit_log;   -- succeeds
COMMIT;
```

There's a test that asserts exactly that (`TestTheAppCanBypassTheAuditTriggerIfItWantsTo`),
because an undocumented limit is one you find out about during an incident.

This falls out of a deliberate choice: **one database user, owning one database**
(see below). Real tamper-resistance needs *two* identities — a privileged one for
migrations and `server purge`, and a restricted one the app connects as, holding no
`DELETE` on `audit_log`. Then the **`GRANT`** does the work, not the trigger. If you
need that guarantee, it's a small change; the seam is there.

One narrow exception is genuinely narrow: the FK that anonymizes `actor_user_id` to
NULL when a user is hard-deleted. The trigger permits that single update *only* if
every other column is byte-for-byte identical — so a GDPR erasure stays possible
without opening a hole.

## The database

**One user, owning one database.** `POSTGRES_USER=app` owns `POSTGRES_DB=app`, and
that's the whole story — the official Postgres image creates the database and makes
the user its owner, so there's no bootstrap SQL and no second role. Migrations, the
app, and `server purge` all use it.

The app never connects as the cluster superuser and never touches another database.
One secret, one connection string.

The cost is stated above: no tamper-proof audit log. That's the trade, taken
knowingly.

**Every entry carries `request_id`, IP, and user agent**, so an entry ties back to
the exact request and its application logs. They ride the context (`audit.WithRequestMeta`)
rather than being threaded through a dozen service signatures.

**It's searchable.** `?action=`, `?actor=`, `?from=`/`?to=`, keyset `?before=`.
Pagination alone is useless at 100k rows: an audit log you can't query is an audit
log nobody reads.

`AUDIT_RETENTION` defaults to **0 = keep forever**. Destroying your compliance
evidence because a config value had a tidy default is not a decision this template
makes for you.

## Isolation is enforced in the application, not the database

Every tenant-owned table has a `tenant_id`, and every repository method that
touches one takes `tenantID` and puts it in the `WHERE` clause — even when the
primary key alone would be unique. Filtering by `id` alone is exactly what turns
a guessed UUID into a cross-tenant read.

This is a deliberate trade. Postgres row-level security would make the database
itself refuse cross-tenant rows, so a forgotten `WHERE` clause could not leak
anything — but it requires every query to run in a transaction with a GUC set,
and it is harder to debug. The template chose the simpler, faster mechanism and
pays for it with a **test**:

`internal/identity/isolation_test.go` proves that a member of one tenant cannot
read, modify, or delete anything in another, even knowing its slug and IDs.
**When you add a tenant-owned resource, add its isolation test there too.** It is
the cheapest insurance in the codebase.

## Sessions, not JWTs

Login issues a random 256-bit token. The database stores only its SHA-256 hash,
so a leak of the `sessions` table hands an attacker nothing usable.

The payoff is revocation. A logout, a password change, or a deactivation takes
effect on the **very next request**, everywhere — where a stateless JWT would
stay valid until it expired. The cost is one indexed lookup per request, which is
the right trade for almost every application that isn't Google.

Passwords use **argon2id** (OWASP's first choice — memory-hard, so GPUs help an
attacker far less than against bcrypt). The cost parameters live inside each
hash, so you can raise them later: existing passwords keep verifying and are
transparently upgraded on the owner's next login.

## Migrations

Plain SQL in `migrations/`, run by [goose](https://github.com/pressly/goose),
**compiled into the binary** with `//go:embed`. The same image is the app and its
own migrator:

```sh
make migrate          # apply
make migrate-status   # what's applied
make migrate-down     # roll back one
```

In `docker-compose.yml` a one-shot `migrate` service runs `server migrate up` and
exits; `app` waits on `service_completed_successfully`, so it can never start
against an unmigrated database. In Kubernetes that identical container is an init
container or a Job.

To add one: create `migrations/00006_widgets.sql` with `-- +goose Up` and
`-- +goose Down` sections. Goose tracks what's applied in a table it owns.

> **Postgres 18+ is required.** Every primary key defaults to the built-in
> `uuidv7()`. v7 IDs are time-ordered, so index inserts append to the rightmost
> leaf instead of scattering random v4s across the B-tree and splitting pages —
> and `ORDER BY id DESC` is a free, stable pagination cursor.

## Configuration

All of it, in `internal/settings`, loaded once at startup from environment
variables — optionally seeded from `.env`, which real env vars always override.
See `.env.example`. Startup **refuses** two unsafe configurations outright:
`APP_DEBUG=true` with `APP_ENV=production` (it would echo internal errors to
callers), and `POSTGRES_SSLMODE=disable` in production.

## The API

```
POST   /api/v1/auth/register              create an account          (rate limited)
POST   /api/v1/auth/login                 -> {token, user}           (rate limited)
POST   /api/v1/auth/password/reset        email a reset link — ALWAYS 204
POST   /api/v1/auth/password/reset/confirm   spend the token; revokes every session
POST   /api/v1/auth/logout                revoke this session
GET    /api/v1/auth/me
POST   /api/v1/auth/password              change password (revokes all sessions)
GET    /api/v1/auth/sessions              your live sessions

GET    /api/v1/tenants                    tenants you belong to
POST   /api/v1/tenants                    create one (you become its owner)
POST   /api/v1/invitations/accept         redeem an invitation token

GET    /api/v1/permissions                    the catalog (public; render your role editor from it)

                                            ── required permission ──
GET    /api/v1/tenants/{tenant}               tenant.read
PATCH  /api/v1/tenants/{tenant}               tenant.update   (name only — slug is immutable)
DELETE /api/v1/tenants/{tenant}               tenant.delete   (SOFT — restorable)

GET    /api/v1/tenants/{tenant}/members       members.read
DELETE /api/v1/tenants/{tenant}/members/me    (none — anyone may leave)
PUT    /api/v1/tenants/{tenant}/members/{userID}/roles   members.update
DELETE /api/v1/tenants/{tenant}/members/{userID}         members.delete

GET    /api/v1/tenants/{tenant}/invitations        invitations.read
POST   /api/v1/tenants/{tenant}/invitations        invitations.create
DELETE /api/v1/tenants/{tenant}/invitations/{id}   invitations.delete

GET    /api/v1/tenants/{tenant}/roles         roles.read
POST   /api/v1/tenants/{tenant}/roles         roles.create
PUT    /api/v1/tenants/{tenant}/roles/{id}    roles.update
DELETE /api/v1/tenants/{tenant}/roles/{id}    roles.delete

GET    /api/v1/tenants/{tenant}/audit         audit.read
       ?action=roles.created &actor=<uuid> &from=/&to=<RFC3339> &before=<cursor>

GET    /api/v1/admin/tenants                    superuser: every tenant, deleted ones flagged
GET    /api/v1/admin/users                      superuser: every user
PATCH  /api/v1/admin/users/{userID}             superuser: activate / deactivate
POST   /api/v1/admin/tenants/{id}/restore       superuser: undelete a tenant

GET    /healthz                           liveness  (never touches the database)
GET    /readyz                            readiness (pings the database)
```

Every tenant-scoped route names the **one** permission it needs, right in
`server.go`'s routing table. Read it top to bottom and you have the entire
authorization policy — which is the point of putting it there instead of
scattering checks through handlers.

The routes with `roles.manage` are additionally subject to the escalation guard
in the service: the permission lets you *operate* the role editor, it does not let
you hand out authority you don't have.

Note `PUT .../members/{userID}/roles` takes the **complete** new role set, not a
delta — so the operation is idempotent and there's no way to apply a change twice
by accident.

A superuser reaching a `/tenants/{tenant}/…` route they have no membership in
holds the full permission set (but **no role** — they aren't a member of
anything), and the access is written to that tenant's audit log. Everyone else
gets 404. There is no `/admin` route that grants superuser.

`/healthz` deliberately does not check the database: if it did, a brief Postgres
blip would make Kubernetes kill every replica, turning a recoverable outage into
a total one. `/readyz` does check, because a replica that can't reach Postgres
should leave the load balancer, not restart.

## Adding your own tenant-scoped resource

1. **Migration** — `migrations/00006_widgets.sql`, with
   `tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`.
2. **Package** — `internal/widgets`, following `internal/identity`: a `Repository`
   taking `database.DB` (so it works with both a pool and a transaction), and a
   `Service` holding the rules. Every method that touches the table takes
   `tenantID` and puts it in the `WHERE` clause.
3. **Routes** — inside the `/tenants/{tenant}` block in `internal/server/server.go`.
   Handlers get the tenant from `tenantFrom(ctx)` and the caller from
   `userFrom(ctx)`; both are guaranteed present by the middleware. Wrap
   administrative routes in `s.requireRole(identity.RoleAdmin)`.
4. **Isolation test** — in `internal/identity/isolation_test.go`, or a sibling.
   Prove tenant A cannot touch tenant B's widgets.
5. **Audit** — call `audit.NewRecorder(tx).Record(...)` inside the same
   transaction as the write, so an action can never happen without being logged.

## Testing

```sh
make test              # unit tests; integration tests SKIP without a database
make test-integration  # starts a throwaway Postgres, runs everything
make test-e2e          # drives the running stack over real HTTP (needs `make up`)
make cover             # same, plus an HTML coverage report
```

**45 test functions, 83 subtests, ~2,800 lines of test** against a real Postgres,
plus **171 HTTP checks** across 5 e2e suites in `scripts/e2e/`. That's roughly a 1:2
test-to-source ratio, deliberately: the properties that matter here — tenant
isolation, the escalation guard, immediate session revocation, the anti-enumeration
behaviour — are exactly the ones you cannot eyeball.

CI (`.github/workflows/ci.yml`) runs four jobs on every push: static checks
(`vet`, `gofmt`, `go mod tidy` freshness, `shellcheck`), tests against a real
Postgres **plus a full migrate down-to-zero-and-back**, the e2e suites against a
real running server, and a Docker image build.

Two CI details worth copying if you fork the pattern:

- **It asserts the integration tests didn't silently skip.** They skip without
  `TEST_POSTGRES_DSN`, which is what keeps `go test ./...` working on a laptop with
  no database — and which would otherwise let a broken DSN turn the whole job green
  while proving nothing.
- **Each e2e suite gets a fresh database.** They each assume they're the only tenant
  in the world, and a leftover row from the previous suite reads as a bug that
  isn't there.

Integration tests run against a **real Postgres**, because what they're checking
*is* the SQL. A mocked database would happily "prove" that a query missing its
`tenant_id` filter is correctly isolated — which is the exact bug they exist to
catch. They apply the same embedded migrations the app ships, so they can't drift
from production's schema.

Using Podman? Every compose target takes an override:
`make test-integration COMPOSE="podman compose"`. (A `docker` shell *alias* won't
work — make runs recipes in `/bin/sh`, which doesn't see your aliases.)

## Email, invitations, and password reset

**Tokens are emailed, never returned by the API.** `POST /invitations` used to hand
the plaintext token back in the response — a hole with a plausible excuse, since it
made the template usable without a mailer. It also meant any admin could mint a
working invitation link for `carol@example.com`, keep it, and redeem it themselves
by registering that address first. The only copy now goes to the invitee's inbox.

With `MAIL_BACKEND=log` (the default) that "inbox" is the application log, so the
link is right there in `docker compose logs app`. That's what keeps the template
runnable with zero setup — and it's exactly why startup **refuses** that backend when
`APP_ENV=production`: those links are working credentials, and this would put them
in your log aggregator.

**Password reset** is the invitation pattern again — a random token, stored only as
its SHA-256 digest, single-use, short TTL (1h; a zero TTL is refused at startup,
because it would mint links that are expired the instant they're created).

Two properties are load-bearing:

- **`POST /auth/password/reset` ALWAYS returns 204.** Unknown address, deactivated
  account, SSO-only user, database failure — all identical. Anything else is a free
  account-enumeration oracle on an unauthenticated endpoint. Which case it *really*
  was gets recorded in the audit log, where the attacker can't see it and you can.
- **Completing a reset revokes every session.** If someone is resetting because
  they were compromised, leaving the attacker's session alive achieves nothing.

## Rate limiting

Guards `/auth/login`, `/auth/register`, `/auth/password/reset`, and
`/invitations/accept`. Login and reset are keyed by **IP *and* email**, and both
must pass — IP alone lets one attacker spray a thousand accounts at one attempt
each and never trip a counter; email alone lets a botnet hammer one account from a
thousand addresses.

Trips return **429** with `Retry-After`, and are **audited** (`access.rate_limited`):
one is noise, a stream from one IP is an attack, and the audit log is the only place
you'd see the difference.

**Know what it is.** It's in-memory, therefore **per-replica**, and a restart forgets
everything. It's a speed bump so an unprotected deployment isn't trivially
brute-forceable — not a wall. The real limiter belongs at your proxy.

## Before you take this to production

The template stops at the point where every project diverges. You need to add:

- **Alerting.** Every denial is written to the audit log *and* emitted as a `WARN`
  log line with a stable `security_event` field — because your alerting can already
  match on a log field, and nobody wants to point it at a Postgres table. Wire rules
  to at least: `superuser.tenant_accessed` (an operator browsing customer data),
  `access.escalation_denied` (rarely innocent), and a burst of `users.login_failed`
  or `users.password_reset_rejected` from one IP (enumeration in progress).
- **A cron for `server purge`.** Retention only takes effect when something runs it.

- **A real mail provider.** `MAIL_BACKEND=log` prints emails (links and all) to
  the application log — which is what makes this runnable with zero setup, and why
  startup *refuses* it when `APP_ENV=production`. `MAIL_BACKEND=smtp` works, but
  most projects will swap in their provider's SDK. The `mail.Mailer` interface is
  the one seam you need to touch.
- **A real rate limiter.** The built-in one is in-memory and therefore
  **per-replica** — three replicas means three times the allowance, and a restart
  forgets everything. It's a speed bump so an unprotected deployment isn't
  trivially brute-forceable. Put the real one at your proxy or WAF, where it sees
  every replica's traffic.
- **A real password for the `app` database user.** It ships as `app`.
- **A second database identity, IF you need a tamper-proof audit log.** Today one
  user owns the database, so a compromised app can erase its own audit trail — see
  "The audit log". Splitting into a privileged migration/purge identity and a
  restricted runtime one closes it.
- **TLS**, terminated at your proxy. Set `SERVER_TRUST_PROXY_HEADERS=true` only
  once a proxy you control is guaranteed to overwrite `X-Forwarded-For` —
  otherwise callers can forge the IPs written into your audit log.
- **Alerting.** The audit log records the events that matter — but nothing *reads*
  it. Wire alerts to at least `superuser.tenant_accessed` (an operator browsing
  customer data), `access.escalation_denied` (rarely innocent), and a burst of
  `users.login_failed` from one IP. Right now they only make rows.
- **A purge job for soft-deleted tenants.** They live in the database forever.
  `AUDIT_RETENTION` handles the audit log; nothing handles the tenants. A
  right-to-erasure request currently has no mechanism behind it.
- **A least-privileged database role.** The app connects as `postgres`. The
  audit-log trigger protects against bugs and injected SQL, but not against a fully
  compromised superuser connection, which could set the purge flag itself. Give the
  app a role with no `DELETE` on `audit_log` and add the `REVOKE` — defence in
  depth: the grant stops the ordinary path, the trigger stops the extraordinary one.
