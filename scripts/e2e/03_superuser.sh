#!/usr/bin/env bash
# Exercise the superuser over the real HTTP API + the real CLI.
set -uo pipefail
API="${API_BASE:-http://localhost:8080}/api/v1"
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
# Registration now sends a VERIFICATION email, and an unverified address cannot
# create a tenant. Click the link, exactly as a real user does — with
# MAIL_BACKEND=log the inbox is the application log.
logs() { ${APP_LOGS:-docker compose logs app} 2>&1; }
verify_email() { logs | grep -o 'token=mtt_ver_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }
verify_last() { req POST /auth/email/verify - "{\"token\":\"$(verify_email)\"}" >/dev/null; }

logs() { ${APP_LOGS:-docker compose logs app} 2>&1; }
login() { req POST /auth/login - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; jqr .token; }

echo "== setup: alice owns acme, root is a plain user =="
req POST /auth/register - '{"email":"alice@example.com","password":"correct-horse-battery","full_name":"Alice"}' >/dev/null
verify_last
req POST /auth/register - '{"email":"root@example.com","password":"correct-horse-battery","full_name":"Root"}' >/dev/null
verify_last
ALICE=$(login alice@example.com)
ROOT=$(login root@example.com)
code=$(req POST /tenants "$ALICE" '{"slug":"acme","name":"Acme Inc"}')
check "alice creates acme" 201 "$code"

echo "== before the grant, root is nobody =="
code=$(req GET /tenants/acme "$ROOT")
check "plain user cannot see acme -> 404" 404 "$code"
code=$(req GET /admin/tenants "$ROOT")
check "plain user hitting /admin -> 404 (not 403)" 404 "$code"
code=$(req GET /admin/users "$ROOT")
check "plain user hitting /admin/users -> 404" 404 "$code"

echo "== grant via CLI (no HTTP route can do this) =="
OUT=$(${APP_EXEC:-docker compose exec -T app} /app/server grant-superuser root@example.com 2>&1)
echo "  CLI: $OUT"
echo "$OUT" | grep -q 'granted superuser to root@example.com' \
  && { echo "  PASS  CLI granted superuser"; pass=$((pass+1)); } \
  || { echo "  FAIL  CLI did not grant"; fail=$((fail+1)); }

# The flag is read per-request from the DB, so the existing token picks it up.
echo "== after the grant =="
code=$(req GET /auth/me "$ROOT")
check "me reports is_superuser" "true" "$(jqr .is_superuser)"

code=$(req GET /admin/tenants "$ROOT")
check "staff surface: list all tenants" 200 "$code"
echo "  INFO  tenants visible to root: $(jq -r '.tenants[].tenant.slug' /tmp/body | tr '\n' ' ')"
check "acme has 1 member" 1 "$(jq -r '.tenants[]|select(.tenant.slug=="acme").member_count' /tmp/body)"

code=$(req GET /admin/users "$ROOT")
check "staff surface: list all users" 200 "$code"
check "sees both users" 2 "$(jq '.users|length' /tmp/body)"

echo "== tenant bypass =="
code=$(req GET /tenants/acme "$ROOT")
check "superuser enters acme without membership" 200 "$code"
# A superuser holds NO role -- they are not a member of anything. They hold the
# entire permission catalog instead, which is what makes every check pass.
check "  ...holding no role (not a member)" 0 "$(jq '.roles|length' /tmp/body)"
check "  ...but the full permission set" 14 "$(jq '.permissions|length' /tmp/body)"
check "  ...flagged via_superuser" "true" "$(jqr .via_superuser)"
code=$(req GET /tenants/acme/members "$ROOT")
check "superuser lists acme's members" 200 "$code"
code=$(req GET /tenants/nope "$ROOT")
check "bypass does not conjure a fake tenant -> 404" 404 "$code"

echo "== alice (a real owner) is NOT flagged =="
code=$(req GET /tenants/acme "$ALICE")
check "alice's access has no via_superuser" "null" "$(jq -r '.via_superuser // "null"' /tmp/body)"

echo "== the bypass is audited =="
code=$(req GET /tenants/acme/audit "$ALICE")
n=$(jq '[.entries[]|select(.action=="superuser.tenant_accessed")]|length' /tmp/body)
echo "  INFO  superuser.tenant_accessed entries: $n"
[ "$n" -eq 2 ] && { echo "  PASS  exactly the 2 real bypasses recorded (the 404 correctly wrote none)"; pass=$((pass+1)); } \
               || { echo "  FAIL  expected exactly 2 bypass entries, got $n"; fail=$((fail+1)); }
echo "  INFO  a recorded entry:"
jq -c '[.entries[]|select(.action=="superuser.tenant_accessed")][0]|{action,metadata}' /tmp/body | sed 's/^/        /'

echo "== deactivation is immediate =="
ALICE_ID=$(req GET /auth/me "$ALICE" >/dev/null; jqr .id)
code=$(req PATCH "/admin/users/$ALICE_ID" "$ROOT" '{"is_active":false}')
check "superuser deactivates alice" 200 "$code"
code=$(req GET /auth/me "$ALICE")
check "alice's live token dies at once -> 401" 401 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "alice cannot log back in -> 401" 401 "$code"

code=$(req PATCH "/admin/users/$ALICE_ID" "$ROOT" '{"is_active":true}')
check "superuser reactivates alice" 200 "$code"
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "alice can log in again" 200 "$code"

ROOT_ID=$(req GET /auth/me "$ROOT" >/dev/null; jqr .id)
code=$(req PATCH "/admin/users/$ROOT_ID" "$ROOT" '{"is_active":false}')
check "superuser cannot deactivate itself -> 400" 400 "$code"

echo "== no HTTP route can grant superuser =="
code=$(req PATCH "/admin/users/$ALICE_ID" "$ROOT" '{"is_superuser":true}')
check "trying to set is_superuser over HTTP -> 400 (unknown field)" 400 "$code"
ALICE=$(login alice@example.com)
code=$(req GET /auth/me "$ALICE")
check "alice is still not a superuser" "false" "$(jqr .is_superuser)"

echo "== revoke via CLI =="
${APP_EXEC:-docker compose exec -T app} /app/server revoke-superuser root@example.com >/dev/null 2>&1
code=$(req GET /admin/tenants "$ROOT")
check "revoked: staff surface gone -> 404" 404 "$code"
code=$(req GET /tenants/acme "$ROOT")
check "revoked: tenant bypass gone -> 404" 404 "$code"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
