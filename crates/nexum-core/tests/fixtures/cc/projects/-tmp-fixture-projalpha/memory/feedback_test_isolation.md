---
name: each integration test gets an isolated temp home
description: tests must use NexumTestHome rather than touching $HOME/.nexum directly
type: feedback
originSessionId: 11111111-1111-4111-8111-111111111111
---

Tests that read or write `~/.nexum/` directly leak state across test runs.

**Why:** Cargo runs tests in parallel by default and shared state produces flaky
failures that take hours to diagnose.

**How to apply:** Always construct paths via `NexumTestHome::new()?.paths()`.
Never call `Paths::resolve()` from a test (that one touches env vars).
