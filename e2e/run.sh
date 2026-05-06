#!/usr/bin/env bash
# nexum e2e harness wrapper.
#
# Usage:
#   ./e2e/run.sh codex          # run codex adapter e2e against bundled fixtures
#   ./e2e/run.sh cc             # run cc adapter e2e against bundled fixtures
#   CODEX_HOME=$HOME/.codex ./e2e/run.sh codex  # use real codex install (read-only)
#   CC_HOME=$HOME/.claude ./e2e/run.sh cc       # use real cc install (read-only)
#
# Env vars:
#   NEXUM_BIN   path to nexum binary (default: ./target/release/nexum)
#   CODEX_HOME  host dir to bind-mount as /root/.codex (codex adapter only)
#   CC_HOME     host dir to bind-mount as /root/.claude (cc adapter)
set -euo pipefail

ADAPTER="${1:-}"
if [ -z "$ADAPTER" ]; then
	echo "usage: $0 <adapter>   (currently supported: codex, cc)" >&2
	exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADAPTER_DIR="$REPO_ROOT/e2e/$ADAPTER"
if [ ! -d "$ADAPTER_DIR" ]; then
	echo "no harness for adapter '$ADAPTER'" >&2
	exit 2
fi

NEXUM_BIN="${NEXUM_BIN:-$REPO_ROOT/target/release/nexum}"
if [ ! -x "$NEXUM_BIN" ]; then
	echo "nexum binary not found at $NEXUM_BIN; building release..." >&2
	(cd "$REPO_ROOT" && cargo build --release -p nexum-cli)
fi

IMAGE_TAG="nexum-e2e:$ADAPTER"
docker build -q -t "$IMAGE_TAG" "$ADAPTER_DIR" >/dev/null

DOCKER_ARGS=(
	--rm
	--network none
	--cap-drop ALL
	--cap-add DAC_READ_SEARCH
	--security-opt no-new-privileges
	-v "$NEXUM_BIN:/usr/local/bin/nexum:ro"
)

case "$ADAPTER" in
codex)
	if [ -n "${CODEX_HOME:-}" ]; then
		if [ ! -d "$CODEX_HOME" ]; then
			echo "CODEX_HOME=$CODEX_HOME does not exist" >&2
			exit 2
		fi
		DOCKER_ARGS+=(-v "$CODEX_HOME:/root/.codex:ro")
	fi
	;;
cc)
	if [ -n "${CC_HOME:-}" ]; then
		if [ ! -d "$CC_HOME" ]; then
			echo "CC_HOME=$CC_HOME does not exist" >&2
			exit 2
		fi
		DOCKER_ARGS+=(-v "$CC_HOME:/root/.claude:ro")
	fi
	;;
*)
	echo "unsupported adapter '$ADAPTER'" >&2
	exit 2
	;;
esac

exec docker run "${DOCKER_ARGS[@]}" "$IMAGE_TAG"
