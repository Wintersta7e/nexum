---
name: prefer tokio::join! over manual joinset for fixed-arity work
description: joinset is for dynamic fan-out; static fan-out reads cleaner with join!
type: feedback
originSessionId: 44444444-4444-4444-8444-444444444444
---

Two parallel async ops with known shape: `tokio::join!(a, b)` returns a tuple
and propagates panics. `JoinSet` is overkill there.

**Why:** simpler call site; no error-collecting boilerplate.

**How to apply:** if you know the fan-out at compile time, use `join!`. Reserve
`JoinSet` for variable counts (e.g., spawning N workers from a runtime input).
