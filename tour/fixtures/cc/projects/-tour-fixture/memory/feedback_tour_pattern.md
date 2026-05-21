---
name: tour pattern for nexum capability validation
description: bundled synthetic CC + Codex records; container builds index, runs each read verb, smokes the MCP server
type: feedback
originSessionId: 00000000-0000-4000-8000-000000000001
---

The tour container generates an ephemeral SSH key, runs `nexum init`,
configures both the CC and Codex adapters against bundled fixtures, builds
the index, exercises every read verb, runs `doctor`, re-runs `index` to
confirm idempotency (zero upserts on the second pass), and finally smokes
the MCP stdio server by handshaking and issuing a search request.

The fixtures live next to this file. They are entirely synthetic — no
real session content, no host paths, no third-party project names. The
slug `-tour-fixture` is a path-encoded placeholder; the surrounding layout
matches what the CC adapter walks under a typical projects directory.

Add additional sibling `.md` files when extending the tour. Each adds one
record to the index and shows up in `list`/`search`/`recent` output.
