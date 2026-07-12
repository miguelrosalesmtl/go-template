#!/usr/bin/env bash
# Tenant lifecycle + the hardened audit log, over the real HTTP API.
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   SERVER_CMD  how to run the server CLI   (default: docker compose exec -T app /app/server)
#   DB_EXEC     how to reach psql           (default: docker compose exec -T postgres)
#   APP_LOGS    how to read the app's log   (default: docker compose logs app)
#               -- the log IS the inbox when MAIL_BACKEND=log
set -uo pipefail
API="${API_BASE:-http://localhost:8080}/api/v1"
PG="${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -tAc"
pass=0; fail=0

# The invitation token is no longer returned by the API -- it is EMAILED. With
# MAIL_BACKEND=log the "inbox" is the application log, so that is where we read it
# from, exactly as a real invitee reads it out of their mail.
invite_token() {  # invite_token <email>
  ${APP_LOGS:-docker compose logs app} 2>&1 \
    | grep -o "token=mtt_inv_[A-Za-z0-9_-]*" | tail -1 | cut -d= -f2
}
reset_token() {   # the newest password-reset link in the log
  ${APP_LOGS:-docker compose logs app} 2>&1 \
    | grep -o "token=mtt_pwr_[A-Za-z0-9_-]*" | tail -1 | cut -d= -f2
}

check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
          else echo "  FAIL  $1: expected $2, got $3"; fail=$((fail+1)); fi; }
req() {
  local m=$1 p=$2 t=$3 d=${4:-}
  local args=(-s -o /tmp/body -w '%{http_code}' -X "$m" "$API$p" -H 'Content-Type: application/json')
  [ "$t" != "-" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-d "$d")
  curl "${args[@]}"
}
jqr() { jq -r "$1" /tmp/body; }
logs() { ${APP_LOGS:-docker compose logs app} 2>&1; }
# Registration now sends a VERIFICATION email, and an unverified address cannot
# create a tenant. Click the link, exactly as a real user does — with MAIL_BACKEND=log
# the inbox is the application log.
verify_email() { logs | grep -o 'token=mtt_ver_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }
reg() {
  req POST /auth/register - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\",\"full_name\":\"$1\"}" >/dev/null
  req POST /auth/email/verify - "{\"token\":\"$(verify_email)\"}" >/dev/null
}
login() { req POST /auth/login - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; jqr .token; }
roleid() { req GET /tenants/acme/roles "$1" >/dev/null; jq -r ".roles[]|select(.key==\"$2\").id" /tmp/body; }

echo "== the catalog is now resource.action CRUD =="
code=$(req GET /permissions -)
check "permission catalog" 200 "$code"
check "14 permissions" 14 "$(jq '.permissions|length' /tmp/body)"
echo "        $(jq -r '.permissions[].key' /tmp/body | tr '\n' ' ')"
check "roles.manage is gone" "false" "$(jq '.permissions|any(.key=="roles.manage")' /tmp/body)"
check "roles.create exists" "true" "$(jq '.permissions|any(.key=="roles.create")' /tmp/body)"
check "invitations.create exists" "true" "$(jq '.permissions|any(.key=="invitations.create")' /tmp/body)"

echo "== setup =="
reg alice@example.com; reg mallory@example.com; reg root@example.com
ALICE=$(login alice@example.com); MALLORY=$(login mallory@example.com)
req POST /tenants "$ALICE" '{"slug":"acme","name":"Acme Inc"}' >/dev/null
ADMIN_ID=$(roleid "$ALICE" admin)
req POST /tenants/acme/invitations "$ALICE" "{\"email\":\"mallory@example.com\",\"role_id\":\"$ADMIN_ID\"}" >/dev/null
TOK=$(invite_token); req POST /invitations/accept "$MALLORY" "{\"token\":\"$TOK\"}" >/dev/null

echo "== the owner really does hold every permission (the bug the tests caught) =="
code=$(req GET /tenants/acme "$ALICE")
check "owner holds all 14" 14 "$(jq '.permissions|length' /tmp/body)"
check "  ...including invitations.delete" "true" "$(jq '.permissions|any(.=="invitations.delete")' /tmp/body)"

echo "== tenant update: name only, slug immutable =="
code=$(req PATCH /tenants/acme "$ALICE" '{"name":"Acme Corporation"}')
check "owner renames the tenant" 200 "$code"
check "  ...name changed" "Acme Corporation" "$(jqr .name)"
check "  ...slug unchanged" "acme" "$(jqr .slug)"
code=$(req PATCH /tenants/acme "$ALICE" '{"slug":"acme-corp"}')
check "trying to change the slug -> 400" 400 "$code"
# The admin role is "everything except tenant.delete", so it DOES hold
# tenant.update. Renaming is an administrative act, not a destructive one.
code=$(req PATCH /tenants/acme "$MALLORY" '{"name":"Acme Corporation"}')
check "admin CAN rename (admin holds tenant.update by design)" 200 "$code"
# ...but not destroy. This is the denial we audit below.
code=$(req DELETE /tenants/acme "$MALLORY")
check "admin CANNOT delete the tenant -> 403" 403 "$code"

echo "== DENIALS ARE AUDITED =="
# The 403 above must have left a trace. Successes alone are a change-history;
# denials are what make it a security trail.
n=$(eval $PG "\"SELECT count(*) FROM audit_log WHERE action='access.denied'\"")
[ "$n" -ge 1 ] && { echo "  PASS  the 403 was recorded as access.denied ($n)"; pass=$((pass+1)); } \
               || { echo "  FAIL  the 403 left no audit trace"; fail=$((fail+1)); }

# Escalation attempt.
OWNER_ID=$(roleid "$ALICE" owner)
req POST /tenants/acme/roles "$MALLORY" '{"key":"backdoor","name":"Backdoor","permissions":["tenant.delete"]}' >/dev/null
n=$(eval $PG "\"SELECT count(*) FROM audit_log WHERE action='access.escalation_denied'\"")
[ "$n" -ge 1 ] && { echo "  PASS  the escalation attempt was recorded ($n)"; pass=$((pass+1)); } \
               || { echo "  FAIL  the escalation attempt left no trace"; fail=$((fail+1)); }
echo "        $(eval $PG "\"SELECT metadata->>'detail' FROM audit_log WHERE action='access.escalation_denied' LIMIT 1\"")"

# Failed logins.
req POST /auth/login - '{"email":"alice@example.com","password":"wrong"}' >/dev/null
req POST /auth/login - '{"email":"nobody@example.com","password":"correct-horse-battery"}' >/dev/null
n=$(eval $PG "\"SELECT count(*) FROM audit_log WHERE action='users.login_failed'\"")
check "failed logins recorded" 2 "$n"
echo "        reasons: $(eval $PG "\"SELECT string_agg(metadata->>'reason',', ') FROM audit_log WHERE action='users.login_failed'\"")"

# Bad invitation token.
req POST /invitations/accept "$MALLORY" '{"token":"mtt_inv_bogus"}' >/dev/null
n=$(eval $PG "\"SELECT count(*) FROM audit_log WHERE action='invitations.rejected'\"")
[ "$n" -ge 1 ] && { echo "  PASS  the bad invitation token was recorded"; pass=$((pass+1)); } \
               || { echo "  FAIL  bad invitation token left no trace"; fail=$((fail+1)); }

echo "== every entry carries request_id / ip / user_agent =="
n=$(eval $PG "\"SELECT count(*) FROM audit_log WHERE request_id <> '' AND ip_address IS NOT NULL AND user_agent <> ''\"")
[ "$n" -ge 5 ] && { echo "  PASS  entries carry request_id + ip + user_agent ($n)"; pass=$((pass+1)); } \
               || { echo "  FAIL  only $n entries have the request metadata"; fail=$((fail+1)); }

echo "== THE AUDIT LOG CANNOT BE REWRITTEN (by anyone, incl. postgres superuser) =="
out=$(${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -c "UPDATE audit_log SET action='nothing.happened'" 2>&1)
echo "$out" | grep -q 'append-only' && { echo "  PASS  UPDATE refused by the database"; pass=$((pass+1)); } \
                                    || { echo "  FAIL  UPDATE was allowed: $out"; fail=$((fail+1)); }
out=$(${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -c "DELETE FROM audit_log" 2>&1)
echo "$out" | grep -q 'append-only' && { echo "  PASS  DELETE refused by the database"; pass=$((pass+1)); } \
                                    || { echo "  FAIL  DELETE was allowed: $out"; fail=$((fail+1)); }
out=$(${DB_EXEC:-docker compose exec -T postgres} psql -U app -d app -c "TRUNCATE audit_log" 2>&1)
echo "$out" | grep -q 'append-only' && { echo "  PASS  TRUNCATE refused (the bypass I nearly shipped)"; pass=$((pass+1)); } \
                                    || { echo "  FAIL  TRUNCATE was allowed: $out"; fail=$((fail+1)); }

echo "== audit search =="
code=$(req GET "/tenants/acme/audit?action=tenants.updated" "$ALICE")
check "filter by action" 200 "$code"
check "  ...2 renames recorded (alice + mallory)" 2 "$(jq '.entries|length' /tmp/body)"
ALICE_ID=$(req GET /auth/me "$ALICE" >/dev/null; jqr .id)
code=$(req GET "/tenants/acme/audit?actor=$ALICE_ID" "$ALICE")
check "filter by actor" 200 "$code"
code=$(req GET "/tenants/acme/audit?action=no.such.action" "$ALICE")
check "an unknown action matches nothing" 0 "$(jq '.entries|length' /tmp/body)"
code=$(req GET "/tenants/acme/audit?from=not-a-date" "$ALICE")
check "a malformed date -> 400" 400 "$code"

echo "== SOFT DELETE =="
code=$(req DELETE /tenants/acme "$MALLORY")
check "admin deleting the tenant (lacks tenant.delete) -> 403" 403 "$code"
code=$(req DELETE /tenants/acme "$ALICE")
check "owner soft-deletes the tenant" 204 "$code"
code=$(req GET /tenants/acme "$ALICE")
check "  ...now 404 for its own OWNER" 404 "$code"
code=$(req GET /tenants/acme "$MALLORY")
check "  ...404 for its members" 404 "$code"
code=$(req GET /tenants "$ALICE")
check "  ...gone from the owner's tenant list" 0 "$(jq '.tenants|length' /tmp/body)"
n=$(eval $PG "\"SELECT count(*) FROM memberships\"")
check "  ...but the memberships survive" 2 "$n"

echo "== the slug is freed, and restore copes =="
BOB=$(reg bob@example.com; login bob@example.com)
code=$(req POST /tenants "$BOB" '{"slug":"acme","name":"Bob Acme"}')
check "somebody else can claim the freed slug" 201 "$code"

${SERVER_CMD:-docker compose exec -T app /app/server} grant-superuser root@example.com >/dev/null 2>&1
ROOT=$(login root@example.com)
code=$(req GET /admin/tenants "$ROOT")
check "superuser sees the deleted tenant" 200 "$code"
DEL_ID=$(jq -r '.tenants[]|select(.tenant.deleted_at != null).tenant.id' /tmp/body)
check "  ...flagged as deleted" "true" "$(jq --arg id "$DEL_ID" '[.tenants[]|select(.tenant.id==$id)][0].tenant.deleted_at != null' /tmp/body)"

code=$(req POST "/admin/tenants/$DEL_ID/restore" "$ROOT" '{}')
check "restoring under the now-taken slug -> 409" 409 "$code"
code=$(req POST "/admin/tenants/$DEL_ID/restore" "$ROOT" '{"slug":"acme-original"}')
check "restoring under a new slug" 200 "$code"
check "  ...new slug" "acme-original" "$(jqr .slug)"
code=$(req GET /tenants/acme-original "$ALICE")
check "the owner has her tenant back" 200 "$code"
check "  ...still owner, whole" "true" "$(jq '.roles|any(.key=="owner")' /tmp/body)"
check "  ...with all 14 permissions" 14 "$(jq '.permissions|length' /tmp/body)"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
