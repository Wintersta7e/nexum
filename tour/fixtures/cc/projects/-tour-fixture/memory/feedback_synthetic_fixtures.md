---
name: keep tour fixtures fully synthetic
description: never derive tour fixtures from real ~/.claude / ~/.codex content; container is sandboxed and ephemeral
type: feedback
originSessionId: 00000000-0000-4000-8000-000000000002
---

Tour fixtures must never be derived from real `~/.claude` or `~/.codex`
content. The container is sandboxed with `--network none --cap-drop ALL
--security-opt no-new-privileges` so a leak inside it cannot exfiltrate.
The danger is in this repository: if a fixture inadvertently captures a
real session id, conversation snippet, or external project name, that
content becomes public the moment the PR lands.

To stay safe: write fresh records by hand; use the all-zero UUID family
(`00000000-0000-4000-8000-000000000000`) for `originSessionId`; reference
only the tour itself, the repository, and generic placeholders. If a
record happens to look like real content during fixture review, rewrite
it before staging.
