---
name: slug-decode ambiguity is a real failure mode
description: prefer git_origin_url + registry signals; treat slug decoding as best-effort fallback only
type: feedback
originSessionId: ffffffff-ffff-4fff-8fff-ffffffffffff
---

When a CC project's encoded cwd-slug contains hyphens, the `/` → `-` substitution
isn't lossless. Two paths that produce the same slug aren't distinguishable from
the slug alone.

**Why:** real cwd paths frequently contain hyphenated directory names. Naive
slug-decoding will silently pick one wrong split and propagate it into
`project_id`, conflating distinct projects.

**How to apply:** the §13 resolution order is `git_origin_url` first, then
registered project names from `config.toml`, then path-based identity from the
slug. Slug-decoded paths are the LAST fallback. When the slug is ambiguous and
no higher-priority signal applies, surface a `nexum doctor` warning and let the
user disambiguate by registering the project explicitly.
