#!/usr/bin/env bash
# RBAC over the real HTTP API: custom roles, permission unions, and — above all —
# every escalation attack I could think of.
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
# create an organization. Click the link, exactly as a real user does — with MAIL_BACKEND=log
# the inbox is the application log.
verify_email() { logs | grep -o 'token=mtt_ver_[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2; }
reg() {
  req POST /auth/register - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\",\"full_name\":\"$1\"}" >/dev/null
  req POST /auth/email/verify - "{\"token\":\"$(verify_email)\"}" >/dev/null
}
login() { req POST /auth/login - "{\"email\":\"$1\",\"password\":\"correct-horse-battery\"}" >/dev/null; jqr .token; }
roleid() { req GET /organizations/acme/roles "$1" >/dev/null; jq -r ".roles[]|select(.key==\"$2\").id" /tmp/body; }
uid() { req GET /auth/me "$1" >/dev/null; jqr .id; }

echo "== setup =="
reg alice@example.com; reg mallory@example.com; reg bob@example.com
ALICE=$(login alice@example.com); MALLORY=$(login mallory@example.com); BOB=$(login bob@example.com)
code=$(req POST /organizations "$ALICE" '{"slug":"acme","name":"Acme Inc"}')
check "alice creates acme (she is owner)" 201 "$code"

OWNER_ID=$(roleid "$ALICE" owner)
ADMIN_ID=$(roleid "$ALICE" admin)
MEMBER_ID=$(roleid "$ALICE" member)

# Derive the catalog size from the API, so adding a permission never silently
# breaks the "owner holds everything" assertions below.
NPERMS=$(req GET /permissions - >/dev/null; jq '.permissions|length' /tmp/body)

echo "== system roles ship seeded =="
code=$(req GET /organizations/acme/roles "$ALICE")
check "list roles" 200 "$code"
check "3 system roles exist" 3 "$(jq '[.roles[]|select(.is_system)]|length' /tmp/body)"
check "owner holds every permission" "$NPERMS" "$(jq '[.roles[]|select(.key=="owner")][0].permissions|length' /tmp/body)"
check "admin lacks organization.delete" "false" "$(jq '[.roles[]|select(.key=="admin")][0].permissions|any(.=="organization.delete")' /tmp/body)"
check "member holds only 2" 2 "$(jq '[.roles[]|select(.key=="member")][0].permissions|length' /tmp/body)"

echo "== invite mallory as admin, bob as member =="
code=$(req POST /organizations/acme/invitations "$ALICE" "{\"email\":\"mallory@example.com\",\"role_id\":\"$ADMIN_ID\"}")
check "invite mallory as admin" 201 "$code"
TOK=$(invite_token); req POST /invitations/accept "$MALLORY" "{\"token\":\"$TOK\"}" >/dev/null
code=$(req POST /organizations/acme/invitations "$ALICE" "{\"email\":\"bob@example.com\",\"role_id\":\"$MEMBER_ID\"}")
TOK=$(invite_token); req POST /invitations/accept "$BOB" "{\"token\":\"$TOK\"}" >/dev/null
code=$(req GET /organizations/acme "$MALLORY")
check "mallory is in acme" 200 "$code"

echo "== permissions gate the routes =="
code=$(req GET /organizations/acme/audit "$BOB")
check "member reading audit -> 403 (lacks audit.read)" 403 "$code"
code=$(req GET /organizations/acme/roles "$BOB")
check "member listing roles -> 403 (lacks roles.read)" 403 "$code"
code=$(req GET /organizations/acme/audit "$MALLORY")
check "admin reading audit -> 200 (has audit.read)" 200 "$code"

echo "== ESCALATION: mallory is an admin with roles.manage =="
code=$(req POST /organizations/acme/roles "$MALLORY" '{"key":"backdoor","name":"Backdoor","permissions":["organization.delete"]}')
check "admin minting a role with organization.delete -> 403" 403 "$code"
echo "        error: $(jqr .error)"

code=$(req POST /organizations/acme/roles "$MALLORY" '{"key":"sneaky","name":"Sneaky","permissions":["members.read","audit.read","organization.delete"]}')
check "...even hidden among permissions she holds -> 403" 403 "$code"

MALLORY_ID=$(uid "$MALLORY")
code=$(req PUT "/organizations/acme/members/$MALLORY_ID/roles" "$MALLORY" "{\"role_ids\":[\"$OWNER_ID\"]}")
check "admin assigning herself the owner role -> 403" 403 "$code"

code=$(req POST /organizations/acme/invitations "$MALLORY" "{\"email\":\"accomplice@example.com\",\"role_id\":\"$OWNER_ID\"}")
check "admin inviting an accomplice as owner -> 403" 403 "$code"

ALICE_ID=$(uid "$ALICE")
code=$(req PUT "/organizations/acme/members/$ALICE_ID/roles" "$MALLORY" "{\"role_ids\":[\"$MEMBER_ID\"]}")
check "admin demoting the owner -> 403" 403 "$code"
code=$(req DELETE "/organizations/acme/members/$ALICE_ID" "$MALLORY")
check "admin removing the owner -> 403" 403 "$code"

echo "== but she CAN build roles within her own authority =="
code=$(req POST /organizations/acme/roles "$MALLORY" '{"key":"auditor","name":"Auditor","permissions":["organization.read","audit.read"]}')
check "admin creates a custom 'auditor' role" 201 "$code"
AUDITOR_ID=$(jqr .id)
check "  ...it is not a system role" "false" "$(jqr .is_system)"

echo "== permissions are the UNION of roles held =="
BOB_ID=$(uid "$BOB")
code=$(req PUT "/organizations/acme/members/$BOB_ID/roles" "$MALLORY" "{\"role_ids\":[\"$MEMBER_ID\",\"$AUDITOR_ID\"]}")
check "give bob member + auditor" 204 "$code"
code=$(req GET /organizations/acme "$BOB")
check "bob now holds 2 roles" 2 "$(jq '.roles|length' /tmp/body)"
check "  ...union includes audit.read (from auditor)" "true" "$(jq '.permissions|any(.=="audit.read")' /tmp/body)"
check "  ...union includes members.read (from member)" "true" "$(jq '.permissions|any(.=="members.read")' /tmp/body)"
check "  ...and nothing else crept in" "false" "$(jq '.permissions|any(.=="roles.create")' /tmp/body)"
code=$(req GET /organizations/acme/audit "$BOB")
check "bob can NOW read the audit log" 200 "$code"

echo "== system roles are immutable, even to the owner =="
code=$(req PUT "/organizations/acme/roles/$ADMIN_ID" "$ALICE" '{"name":"Hijacked","permissions":["organization.read"]}')
check "owner editing the system 'admin' role -> 403" 403 "$code"
code=$(req DELETE "/organizations/acme/roles/$ADMIN_ID" "$ALICE")
check "owner deleting a system role -> 403" 403 "$code"
code=$(req POST /organizations/acme/roles "$ALICE" '{"key":"admin","name":"My Admin","permissions":["organization.read"]}')
check "reusing a system role's key -> 409" 409 "$code"

echo "== a role in use cannot be deleted =="
code=$(req DELETE "/organizations/acme/roles/$AUDITOR_ID" "$ALICE")
check "deleting a role bob still holds -> 409" 409 "$code"
code=$(req PUT "/organizations/acme/members/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\"]}")
check "reassign bob off the auditor role" 204 "$code"
code=$(req DELETE "/organizations/acme/roles/$AUDITOR_ID" "$ALICE")
check "now it deletes" 204 "$code"

echo "== a permission no code enforces is refused =="
code=$(req POST /organizations/acme/roles "$ALICE" '{"key":"fake","name":"Fake","permissions":["billing.refund"]}')
check "role with an invented permission -> 400" 400 "$code"
echo "        error: $(jqr .error)"

echo "== invariants =="
code=$(req PUT "/organizations/acme/members/$ALICE_ID/roles" "$ALICE" "{\"role_ids\":[\"$ADMIN_ID\"]}")
check "sole owner stripping her own owner role -> 409" 409 "$code"
code=$(req PUT "/organizations/acme/members/$BOB_ID/roles" "$ALICE" '{"role_ids":[]}')
check "leaving a member with zero roles -> 400" 400 "$code"

echo "== cross-organization role isolation =="
req POST /organizations "$BOB" '{"slug":"globex","name":"Globex"}' >/dev/null
code=$(req POST /organizations/globex/roles "$BOB" '{"key":"secret","name":"Secret","permissions":["audit.read"]}')
check "bob creates a role in HIS organization" 201 "$code"
SECRET_ID=$(jqr .id)
# Alice is an OWNER of acme (all permissions) — only organization scoping can stop her.
code=$(req PUT "/organizations/acme/members/$BOB_ID/roles" "$ALICE" "{\"role_ids\":[\"$MEMBER_ID\",\"$SECRET_ID\"]}")
check "acme's owner assigning globex's role -> 404" 404 "$code"
code=$(req PUT "/organizations/acme/roles/$SECRET_ID" "$ALICE" '{"name":"Hijacked","permissions":["organization.read"]}')
check "acme's owner editing globex's role -> 404" 404 "$code"
code=$(req DELETE "/organizations/acme/roles/$SECRET_ID" "$ALICE")
check "acme's owner deleting globex's role -> 404" 404 "$code"

echo "== the audit log records role changes =="
code=$(req GET /organizations/acme/audit "$ALICE")
echo "  INFO  RBAC actions recorded:"
jq -r '.entries[]|select(.action|startswith("roles.") or startswith("members.updated"))|"        \(.action)  \(.metadata|tostring)"' /tmp/body | head -5
n=$(jq '[.entries[]|select(.action=="roles.created" or .action=="roles.deleted" or .action=="members.updated")]|length' /tmp/body)
[ "$n" -ge 3 ] && { echo "  PASS  role changes are audited ($n entries)"; pass=$((pass+1)); } \
               || { echo "  FAIL  expected >=3 RBAC audit entries, got $n"; fail=$((fail+1)); }

echo
echo "======================================"
echo "  PASSED: $pass   FAILED: $fail"
echo "======================================"
[ "$fail" -eq 0 ]
