---
name: current branch / commit / PR workflow
description: trunk-based; small commits per task; PRs only when reviewable in <30 min
type: project
originSessionId: 55555555-5555-4555-8555-555555555555
---

Trunk-based development on `main`. No long-lived feature branches; rebase
locally if needed.

**Commit policy:** one commit per logical task. The phase plans drive the
granularity (each task in a phase plan == one commit). The three-command gate
must pass before any commit (CI enforces).

**PR policy:** PRs only when the diff is reviewable in under 30 minutes. Larger
changes get split into a series of PRs with a tracking issue.
