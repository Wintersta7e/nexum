---
name: pattern for repeatable adapter validation
description: bundled synthetic fixtures + bind-mounted host data via env var; default flow ingests fixtures only
type: feedback
originSessionId: 11111111-1111-4111-8111-111111111111
---

The harness defaults to bundled synthetic fixtures so it has no dependency on
host state. The container generates an ephemeral SSH key, runs nexum init,
points config at the staged fixture dir, indexes, and exercises the read
verbs. Set the relevant env var (e.g. CC_HOME) to bind-mount your real
install read-only and exercise the adapter against production-shaped data
without granting the container any write access.
