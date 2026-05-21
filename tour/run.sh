#!/usr/bin/env bash
# nexum capability tour — host-side wrapper.
#
# Builds the `nexum` and `nexum-mcp` release binaries, builds the tour
# image, then runs the tour inside an isolated container with the
# bundled synthetic fixtures.
#
# Usage:
#   ./tour/run.sh
#
# Env vars:
#   NEXUM_BIN      path to nexum CLI binary (default: ./target/release/nexum)
#   NEXUM_MCP_BIN  path to nexum-mcp binary (default: ./target/release/nexum-mcp)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOUR_DIR="$REPO_ROOT/tour"

NEXUM_BIN="${NEXUM_BIN:-$REPO_ROOT/target/release/nexum}"
NEXUM_MCP_BIN="${NEXUM_MCP_BIN:-$REPO_ROOT/target/release/nexum-mcp}"

if [ ! -x "$NEXUM_BIN" ] || [ ! -x "$NEXUM_MCP_BIN" ]; then
	echo "release binaries missing; building..." >&2
	(cd "$REPO_ROOT" && cargo build --locked --release -p nexum-cli -p nexum-mcp)
fi

IMAGE_TAG="nexum-tour:latest"

# Tar-pipe the build context so docker never sees the Windows-mount path
# directly (defuses the WSL + Docker Desktop bind-mount registration
# trap; harmless on plain Linux).
tar -C "$TOUR_DIR" -cf - . | docker build -q -t "$IMAGE_TAG" - >/dev/null

# Best-effort cleanup of any Docker Desktop bind-mount registration left
# over from `docker build`. No-op on Linux runners that don't have
# wsl.exe in PATH.
__release_bind_mounts() {
	if command -v wsl.exe >/dev/null 2>&1; then
		wsl.exe --terminate docker-desktop >/dev/null 2>&1 || true
	fi
}
trap __release_bind_mounts EXIT

docker run \
	--rm \
	--network none \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	-v "$NEXUM_BIN:/usr/local/bin/nexum:ro" \
	-v "$NEXUM_MCP_BIN:/usr/local/bin/nexum-mcp:ro" \
	"$IMAGE_TAG"
