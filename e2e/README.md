# nexum end-to-end test harness

Reproducible real-world tests against the codex / cc native-memory adapters,
fully isolated inside a Docker container. The container generates an ephemeral
SSH key, runs `nexum init`, exercises an `nexum index` pass, and runs the read
verbs against the resulting database.

The harness exists because some classes of bug (file-format quirks, lazy
materialization on first read, signed-commit roundtrips, IO edge cases) only
surface against a real install on a real filesystem — unit-test fixtures
pre-arrange too much state to catch them.

## Adapters

- [`codex/`](codex/) — codex adapter (reads `<memories_dir>/MEMORY.md`,
  `<memories_dir>/rollout_summaries/`, and `<state_db>` for thread metadata).
- `cc/` — cc adapter, planned.

## Quick start (codex)

```bash
# Build the release binary, build the image, run the test against bundled fixtures.
./e2e/run.sh codex
```

The default flow uses synthetic fixtures bundled in this repo. No real codex
memory data is mounted; no host paths are read.

## Testing against your real codex install

Override the mount path via env var. The container always reads it as `:ro`:

```bash
CODEX_HOME="$HOME/.codex" ./e2e/run.sh codex
```

`CODEX_HOME` is bound at `/root/.codex` inside the container, replacing the
bundled fixtures. The container still uses an ephemeral SSH key, ephemeral
`~/.nexum/`, and `--rm` on exit — your host is untouched.

## Env vars

| Var          | Default                            | Purpose                               |
|--------------|------------------------------------|---------------------------------------|
| `NEXUM_BIN`  | `./target/release/nexum`           | Host path to the nexum binary.        |
| `CODEX_HOME` | _(bundled fixtures)_               | Codex install dir to mount read-only. |
| `CC_HOME`    | _(bundled fixtures, when added)_   | CC install dir to mount read-only.    |

## Hygiene

Anything committed under `e2e/` is scanned by the project's hygiene grep
alongside `crates/`. No real user names, emails, paths, fingerprints, or
external project identifiers belong here. Fixtures are intentionally
generic so they describe the harness itself rather than any external work.
