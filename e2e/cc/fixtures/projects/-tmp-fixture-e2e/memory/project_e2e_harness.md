---
name: purpose and shape of the bundled fixture
description: synthetic CC-style memory used by the e2e harness; not a real work record
type: project
originSessionId: 22222222-2222-4222-8222-222222222222
---

This fixture exists only so the e2e harness has well-formed YAML-frontmatter
records to ingest. The slug `-tmp-fixture-e2e` is a path-encoded placeholder;
the surrounding directory layout matches what the adapter walks under
`<projects_dir>/<slug>/memory/`.

Two records here let the harness assert non-zero ingest counts and exercise
the FTS path against a non-empty corpus.
