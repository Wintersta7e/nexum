#!/usr/bin/env bash
# CC adapter e2e — runs inside the harness container.
# Layout assumed by entrypoint:
#   /usr/local/bin/nexum     — bind-mounted release binary (read-only)
#   /root/.claude/projects/  — bind-mounted projects dir (read-only;
#                              defaults to bundled fixtures from /work/fixtures)
set -euo pipefail

hr() { printf '\n========== %s ==========\n' "$1"; }

# Fall back to bundled fixtures if the host didn't bind-mount /root/.claude.
if [ ! -d /root/.claude/projects ]; then
	mkdir -p /root/.claude
	cp -r /work/fixtures/projects /root/.claude/projects
fi

# Stage a writable copy so any adapter-side caching has a writable target.
# The mounted host dir is :ro by contract.
STAGE=/tmp/cc-staging
mkdir -p "$STAGE"
cp -r /root/.claude/projects "$STAGE/projects"
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

hr "3/5  Configure: cc-only against staged fixtures"
sed -i '/^\[adapters\.codex\]/,/^\[/{s/^enabled = true$/enabled = false/;}' "$HOME/.nexum/config.toml"
sed -i '/^\[adapters\.local\]/,/^\[/{s/^enabled = true$/enabled = false/;}' "$HOME/.nexum/config.toml"
sed -i "s|^projects_dir = .*|projects_dir = \"$STAGE/projects\"|" "$HOME/.nexum/config.toml"
echo "Config (cc section):"
grep -E '^\[adapters\.cc\]|^enabled|^projects_dir|^max_age_years' "$HOME/.nexum/config.toml" | sed -n '1,5p'

hr "4/5  nexum index --json"
nexum index --json

hr "5/5  Read verbs"
echo "--- nexum recent --json ---"
nexum recent --json | head -40
echo
echo "--- nexum search --json 'fixture' ---"
nexum search --json "fixture" | head -40

hr "DONE"
echo "Records in index:"
sqlite3 "$HOME/.nexum/index.db" "SELECT COUNT(*) FROM records;"
