#!/usr/bin/env bash
# Drive the real HTTP API end to end: register -> login -> create tenant ->
# invite -> accept -> role change -> isolation probe -> audit log.
#
# Overridable so these run against compose OR a plain binary (see .github/workflows):
#   API_BASE    where the API is            (default http://localhost:8080)
#   SERVER_CMD  how to run the server CLI   (default: docker compose exec -T app /app/server)
#   DB_EXEC     how to reach psql           (default: docker compose exec -T postgres)
#   APP_LOGS    how to read the app's log   (default: docker compose logs app)
#               -- the log IS the inbox when MAIL_BACKEND=log
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

check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1: expected $2, got $3"; fail=$((fail+1)); fi
}

# Returns the HTTP status; writes body to /tmp/body
req() { # req <method> <path> <token|-> [json]
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
roleid() { req GET "/tenants/$1/roles" "$2" >/dev/null; jq -r ".roles[]|select(.key==\"$3\").id" /tmp/body; }

echo "== register =="
code=$(req POST /auth/register - '{"email":"alice@example.com","password":"correct-horse-battery","full_name":"Alice"}')
check "register alice" 201 "$code"
verify_last
code=$(req POST /auth/register - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "duplicate email -> 409" 409 "$code"
code=$(req POST /auth/register - '{"email":"bob@example.com","password":"correct-horse-battery","full_name":"Bob"}')
check "register bob" 201 "$code"
verify_last
code=$(req POST /auth/register - '{"email":"carol@example.com","password":"correct-horse-battery","full_name":"Carol"}')
check "register carol" 201 "$code"
verify_last
code=$(req POST /auth/register - '{"email":"x@example.com","password":"short"}')
check "short password -> 400" 400 "$code"

echo "== login =="
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
check "login alice" 200 "$code"
ALICE=$(jqr .token)
[ -n "$ALICE" ] && [ "$ALICE" != null ] && echo "  PASS  got a token: ${ALICE:0:16}..." && pass=$((pass+1))

code=$(req POST /auth/login - '{"email":"alice@example.com","password":"wrong-password"}')
check "wrong password -> 401" 401 "$code"
code=$(req POST /auth/login - '{"email":"nobody@example.com","password":"correct-horse-battery"}')
check "unknown email -> 401" 401 "$code"

code=$(req POST /auth/login - '{"email":"bob@example.com","password":"correct-horse-battery"}')
BOB=$(jqr .token)
code=$(req POST /auth/login - '{"email":"carol@example.com","password":"correct-horse-battery"}')
CAROL=$(jqr .token)

echo "== auth guards =="
code=$(req GET /auth/me - )
check "no token -> 401" 401 "$code"
code=$(req GET /auth/me "garbage-token")
check "bad token -> 401" 401 "$code"
code=$(req GET /auth/me "$ALICE")
check "me with a good token" 200 "$code"
check "me is alice" "alice@example.com" "$(jqr .email)"
check "password hash is not exposed" "null" "$(jq -r '.password_hash // "null"' /tmp/body)"

echo "== tenants =="
code=$(req POST /tenants "$ALICE" '{"slug":"acme","name":"Acme Inc"}')
check "alice creates acme" 201 "$code"
code=$(req POST /tenants "$BOB" '{"slug":"globex","name":"Globex Corp"}')
check "bob creates globex" 201 "$code"
code=$(req POST /tenants "$ALICE" '{"slug":"api","name":"Reserved"}')
check "reserved slug -> 400" 400 "$code"
code=$(req POST /tenants "$ALICE" '{"slug":"acme","name":"Dupe"}')
check "duplicate slug -> 409" 409 "$code"

code=$(req GET /tenants/acme "$ALICE")
check "alice reads acme" 200 "$code"
check "alice is owner" "true" "$(jq '.roles|any(.key=="owner")' /tmp/body)"

echo "== ISOLATION =="
code=$(req GET /tenants/globex "$ALICE")
check "alice reading globex -> 404 (not 403)" 404 "$code"
code=$(req GET /tenants/acme "$BOB")
check "bob reading acme -> 404" 404 "$code"
code=$(req GET /tenants/globex/members "$ALICE")
check "alice listing globex members -> 404" 404 "$code"
code=$(req GET /tenants/nonexistent "$ALICE")
check "nonexistent tenant -> 404 (same as forbidden)" 404 "$code"

echo "== invitations =="
MEMBER_ID=$(roleid acme "$ALICE" member)
code=$(req POST /tenants/acme/invitations "$ALICE" "{\"email\":\"carol@example.com\",\"role_id\":\"$MEMBER_ID\"}")
check "alice invites carol" 201 "$code"
INV=$(invite_token)

code=$(req POST /invitations/accept "$BOB" "{\"token\":\"$INV\"}")
check "BOB stealing carol's invite -> 400" 400 "$code"

code=$(req POST /invitations/accept "$CAROL" "{\"token\":\"$INV\"}")
check "carol accepts her own invite" 200 "$code"
check "carol joined acme" "acme" "$(jqr .slug)"

code=$(req POST /invitations/accept "$CAROL" "{\"token\":\"$INV\"}")
check "replaying a spent invite -> 400" 400 "$code"

code=$(req GET /tenants/acme "$CAROL")
check "carol can now read acme" 200 "$code"
check "carol is a member" "true" "$(jq '.roles|any(.key=="member")' /tmp/body)"

echo "== role enforcement =="
CAROL_ID=$(req GET /tenants/acme/members "$ALICE" >/dev/null; jq -r '.members[]|select(.email=="carol@example.com").user_id' /tmp/body)
code=$(req POST /tenants/acme/invitations "$CAROL" "{\"email\":\"dave@example.com\",\"role_id\":\"$MEMBER_ID\"}")
check "member inviting -> 403" 403 "$code"
code=$(req GET /tenants/acme/audit "$CAROL")
check "member reading audit -> 403" 403 "$code"

ADMIN_ID=$(roleid acme "$ALICE" admin)
code=$(req PUT "/tenants/acme/members/$CAROL_ID/roles" "$ALICE" "{\"role_ids\":[\"$ADMIN_ID\"]}")
check "owner promotes carol to admin" 204 "$code"
code=$(req POST /tenants/acme/invitations "$CAROL" "{\"email\":\"dave@example.com\",\"role_id\":\"$MEMBER_ID\"}")
check "admin can now invite" 201 "$code"

ALICE_ID=$(req GET /auth/me "$ALICE" >/dev/null; jqr .id)
code=$(req PUT "/tenants/acme/members/$ALICE_ID/roles" "$CAROL" "{\"role_ids\":[\"$MEMBER_ID\"]}")
check "admin demoting the owner -> 403" 403 "$code"
OWNER_ID=$(roleid acme "$ALICE" owner)
code=$(req PUT "/tenants/acme/members/$CAROL_ID/roles" "$CAROL" "{\"role_ids\":[\"$OWNER_ID\"]}")
check "admin self-promoting to owner -> 403" 403 "$code"

echo "== last owner =="
code=$(req DELETE "/tenants/acme/members/me" "$ALICE")
check "sole owner leaving -> 409" 409 "$code"

echo "== sessions =="
code=$(req GET /auth/sessions "$ALICE")
check "list sessions" 200 "$code"
code=$(req POST /auth/logout "$ALICE" )
check "logout" 204 "$code"
code=$(req GET /auth/me "$ALICE")
check "revoked token -> 401 immediately" 401 "$code"
code=$(req GET /auth/me "$BOB")
check "bob's session unaffected" 200 "$code"

echo "== audit =="
code=$(req POST /auth/login - '{"email":"alice@example.com","password":"correct-horse-battery"}')
ALICE=$(jqr .token)
code=$(req GET /tenants/acme/audit "$ALICE")
check "owner reads audit log" 200 "$code"
n=$(jq '.entries|length' /tmp/body)
echo "  INFO  acme audit entries: $n"
jq -r '.entries[]|"        \(.action)"' /tmp/body | head -8
foreign=$(jq -r '[.entries[]|select(.tenant_id==null)]|length' /tmp/body)
check "no foreign/null tenant entries in acme's log" 0 "$foreign"

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
