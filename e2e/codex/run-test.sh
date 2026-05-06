#!/usr/bin/env bash
# Codex adapter e2e — runs inside the harness container.
# Layout assumed by entrypoint:
#   /usr/local/bin/nexum     — bind-mounted release binary (read-only)
#   /root/.codex/            — bind-mounted memories + state_db (read-only;
#                              defaults to bundled fixtures from /work/fixtures)
set -euo pipefail

hr() { printf '\n========== %s ==========\n' "$1"; }

# If the host didn't bind-mount /root/.codex, fall back to the bundled fixtures
# baked into the image at /work/fixtures. Either way the container treats it
# as read-only — writes go to /tmp/codex-staging which is in the container's
# writable overlay.
if [ ! -d /root/.codex ]; then
	cp -r /work/fixtures /root/.codex
fi

# Stage a writable copy so the indexer can join thread metadata. The mounted
# /root/.codex is read-only by contract.
STAGE=/tmp/codex-staging
mkdir -p "$STAGE"
cp -r /root/.codex/memories "$STAGE/memories"
if [ -f /root/.codex/state_5.sqlite ]; then
	cp /root/.codex/state_5.sqlite "$STAGE/state_5.sqlite"
else
	# Minimal threads-table sqlite so the adapter's join path has a target.
	sqlite3 "$STAGE/state_5.sqlite" \
		"CREATE TABLE threads (id TEXT, rollout_path TEXT, cwd TEXT, \
         git_origin_url TEXT, created_at TEXT, updated_at TEXT, title TEXT);"
fi
chmod -R u+rw "$STAGE"

hr "1/5  Generate ed25519 SSH key"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -C "nexum-e2e" -q
ssh-keygen -lf "$HOME/.ssh/id_ed25519"
git config --global user.signingkey "$HOME/.ssh/id_ed25519"

hr "2/5  nexum init -y"
nexum init -y
echo
echo "Bootstrap commit:"
git -C "$HOME/.nexum/notebook.git" log --oneline -1
echo
echo "Verify bootstrap signature:"
git -C "$HOME/.nexum/notebook.git" verify-commit HEAD 2>&1 || true

hr "3/5  Configure: codex-only against staged fixtures"
sed -i '/^\[adapters\.cc\]/,/^\[/{s/^enabled = true$/enabled = false/;}' "$HOME/.nexum/config.toml"
sed -i '/^\[adapters\.local\]/,/^\[/{s/^enabled = true$/enabled = false/;}' "$HOME/.nexum/config.toml"
sed -i "s|^memories_dir = .*|memories_dir = \"$STAGE/memories\"|" "$HOME/.nexum/config.toml"
sed -i "s|^state_db = .*|state_db = \"$STAGE/state_5.sqlite\"|" "$HOME/.nexum/config.toml"
echo "Config (codex section):"
grep -E '^\[adapters\.codex\]|^enabled|^memories_dir|^state_db' "$HOME/.nexum/config.toml" | sed -n '1,5p'

hr "4/5  nexum index --json"
nexum index --json

hr "5/5  Read verbs"
echo "--- nexum recent --json ---"
nexum recent --json | head -40
echo
echo "--- nexum search --json 'roundtrip' ---"
nexum search --json "roundtrip" | head -40

hr "DONE"
echo "Records in index:"
sqlite3 "$HOME/.nexum/index.db" "SELECT COUNT(*) FROM records;"
