# tour

A reproducible capability tour for nexum. Exercises every read-path verb
plus `doctor`, re-index idempotency, and a `nexum-mcp` stdio smoke test
inside a sandboxed Linux container against fully synthetic fixtures.

## Run

```bash
./tour/run.sh
```

The wrapper builds `nexum` + `nexum-mcp` release binaries (if missing),
builds the `nexum-tour:latest` image, and runs the container with:

- `--network none`         no outbound traffic
- `--cap-drop ALL`         no Linux capabilities
- `--security-opt no-new-privileges`
- Bind-mounts the release binaries read-only; everything else is
  ephemeral container state.

## What it covers

| Step | Verb / surface         | Assertion                                    |
|----:|------------------------|----------------------------------------------|
| 1   | `ssh-keygen`           | ed25519 key + git signing config             |
| 2   | `nexum init -y`        | bootstrap commit signature verifies          |
| 3   | adapter config         | CC + Codex on, Local off                     |
| 4   | `nexum index --json`   | `ingested >= 4` (3 CC + 1 Codex)             |
| 5   | `nexum recent --json`  | `results >= 1`                               |
| 6   | `nexum search --json`  | `results >= 1` for query `tour`              |
| 7   | `nexum list --json`    | `results >= 1`                               |
| 8   | `nexum get <id>`       | id round-trips through `get`                 |
| 9   | `nexum by-session`     | invoked against a fixture session UUID       |
| 10  | `nexum project`        | project verb invoked                         |
| 11  | `nexum doctor --json`  | zero `Critical` findings                     |
| 12  | re-index               | `upserted == 0` (idempotent)                 |
| 13  | `nexum-mcp` stdio      | initialize round-trips, `serverInfo.name` ok |

## Fixtures

All bundled fixtures (`tour/fixtures/cc/`, `tour/fixtures/codex/`) are
synthetic. They do not derive from any real `~/.claude` or `~/.codex`
content; UUIDs use the all-zero family
(`00000000-0000-4000-8000-000000000XXX`), project slugs are placeholders
(`-tour-fixture`), and record bodies reference only the tour itself.

When extending the tour, write new fixtures by hand and review them
before staging — anything that lands in `tour/fixtures/` is public.
