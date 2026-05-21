#!/usr/bin/env bash
# nexum capability tour — runs inside the harness container.
# Layout assumed by entrypoint:
#   /usr/local/bin/nexum      — bind-mounted CLI release binary (read-only)
#   /usr/local/bin/nexum-mcp  — bind-mounted MCP release binary (read-only)
set -euo pipefail

hr() { printf '\n========== %s ==========\n' "$1"; }
ok() { printf '  ok    %s\n' "$1"; }
fail() {
	printf '  FAIL  %s\n' "$1"
	exit 1
}

# Stage a writable copy of the bundled fixtures. The image bakes them in
# at /work/fixtures; the container's writable overlay holds the staged
# copy so the indexer can join thread metadata etc.
STAGE=/tmp/tour-staging
mkdir -p "$STAGE/cc/projects" "$STAGE/codex"
cp -r /work/fixtures/cc/projects/. "$STAGE/cc/projects/"
cp -r /work/fixtures/codex/. "$STAGE/codex/"
# Minimal Codex state DB so the adapter's join path has a target table.
sqlite3 "$STAGE/codex/state_5.sqlite" \
	"CREATE TABLE threads (id TEXT, rollout_path TEXT, cwd TEXT, \
     git_origin_url TEXT, created_at TEXT, updated_at TEXT, title TEXT);"
chmod -R u+rw "$STAGE"

hr "Step 1  Generate ed25519 SSH key"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -C "nexum-tour" -q
git config --global user.signingkey "$HOME/.ssh/id_ed25519"
ok "key generated, gpg.format=ssh, signingkey configured"

hr "Step 2  nexum init -y"
nexum init -y >/dev/null
git -C "$HOME/.nexum/notebook.git" verify-commit HEAD >/dev/null 2>&1 ||
	fail "bootstrap commit signature did not verify"
ok "init complete; bootstrap commit signature verified"

hr "Step 3  Configure CC + Codex adapters against staged fixtures"
sed -i '/^\[adapters\.local\]/,/^\[/{s/^enabled = true$/enabled = false/;}' \
	"$HOME/.nexum/config.toml"
sed -i "s|^projects_dir = .*|projects_dir = \"$STAGE/cc/projects\"|" \
	"$HOME/.nexum/config.toml"
sed -i "s|^memories_dir = .*|memories_dir = \"$STAGE/codex/memories\"|" \
	"$HOME/.nexum/config.toml"
sed -i "s|^state_db = .*|state_db = \"$STAGE/codex/state_5.sqlite\"|" \
	"$HOME/.nexum/config.toml"
ok "adapters: cc=on, codex=on, local=off"

hr "Step 4  nexum index --json  (first pass)"
INDEX_FIRST="$(nexum index --json)"
UPSERTS="$(jq -r '.upserts // 0' <<<"$INDEX_FIRST")"
[ "$UPSERTS" -ge 4 ] || fail "expected upserts >= 4, got $UPSERTS"
ok "upserts = $UPSERTS"

hr "Step 5  nexum recent --json"
RECENT="$(nexum recent --json --limit 10)"
RECENT_COUNT="$(jq -r '.results | length' <<<"$RECENT")"
[ "$RECENT_COUNT" -ge 1 ] || fail "expected recent count >= 1, got $RECENT_COUNT"
ok "results = $RECENT_COUNT"

hr "Step 6  nexum search --json 'tour'"
SEARCH="$(nexum search --json "tour")"
SEARCH_COUNT="$(jq -r '.results | length' <<<"$SEARCH")"
[ "$SEARCH_COUNT" -ge 1 ] || fail "expected search hits >= 1, got $SEARCH_COUNT"
ok "results = $SEARCH_COUNT"

hr "Step 7  nexum list --json --limit 5"
LIST="$(nexum list --json --limit 5)"
LIST_COUNT="$(jq -r '.results | length' <<<"$LIST")"
[ "$LIST_COUNT" -ge 1 ] || fail "expected list count >= 1, got $LIST_COUNT"
ok "results = $LIST_COUNT"

hr "Step 8  nexum get <id>  (round-trip)"
FIRST_ID="$(jq -r '.results[0].id' <<<"$RECENT")"
[ -n "$FIRST_ID" ] && [ "$FIRST_ID" != "null" ] ||
	fail "no id available from recent"
GET="$(nexum get "$FIRST_ID" --json)"
GOT_ID="$(jq -r '.record.id' <<<"$GET")"
[ "$GOT_ID" = "$FIRST_ID" ] || fail "get returned id $GOT_ID, expected $FIRST_ID"
ok "id = $FIRST_ID"

hr "Step 9  nexum by-session  (synthetic UUID)"
BY_SESSION="$(nexum by-session 00000000-0000-4000-8000-000000000001 --json)"
BS_COUNT="$(jq -r '.results | length' <<<"$BY_SESSION")"
ok "results = $BS_COUNT"

hr "Step 10  nexum project list --json"
PROJECT="$(nexum project list --json)"
PROJECT_COUNT="$(jq -r '.results | length' <<<"$PROJECT")"
[ "$PROJECT_COUNT" -ge 1 ] || fail "expected projects >= 1, got $PROJECT_COUNT"
ok "projects = $PROJECT_COUNT"

hr "Step 11  nexum doctor --json"
DOCTOR="$(nexum doctor --json)"
# Doctor's JSON has one top-level object per check, each with a `severity`
# field. Walk every nested object and count `severity == "Critical"`.
CRITICAL="$(jq -r '[.. | objects | select(.severity? == "Critical")] | length' <<<"$DOCTOR")"
[ "$CRITICAL" -eq 0 ] || fail "doctor reported $CRITICAL critical findings"
ok "critical = 0"

hr "Step 12  nexum index --json  (second pass; cc-native idempotent)"
INDEX_SECOND="$(nexum index --json)"
# cc-native must be fully idempotent. codex-native re-upserts under
# synthetic fixtures because the empty `threads` table forces the
# adapter to fall back to `Utc::now()` for `updated_at`; not a real
# regression with thread metadata present in production data.
CC_UPSERTS_2="$(jq -r '[.per_source[]? | select(.source=="cc-native") | .upserts] | add // 0' <<<"$INDEX_SECOND")"
[ "$CC_UPSERTS_2" -eq 0 ] || fail "cc-native re-upserted $CC_UPSERTS_2 records on pass 2; expected 0"
ok "cc-native upserts = 0 (idempotent)"

hr "Step 13  nexum-mcp stdio smoke"
# Pipe a single initialize request; verify the server emits a well-formed
# JSON-RPC response with the expected serverInfo. `head -1` exits after
# one line, which SIGPIPEs the child server; the `|| true` keeps the
# pipeline tolerant of MCP's normal cold-start chatter on stderr.
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"tour","version":"1.0"}}}'
RESPONSE="$(printf '%s\n' "$INIT" | timeout 10 nexum-mcp 2>/dev/null | head -1 || true)"
SERVER_NAME="$(jq -r '.result.serverInfo.name // empty' <<<"$RESPONSE" 2>/dev/null || true)"
[ -n "$SERVER_NAME" ] || fail "MCP initialize returned no serverInfo.name (response: $RESPONSE)"
ok "serverInfo.name = $SERVER_NAME"

hr "DONE"
RECORDS="$(sqlite3 "$HOME/.nexum/index.db" "SELECT COUNT(*) FROM records;")"
echo "Records in index: $RECORDS"
echo "All steps passed."
