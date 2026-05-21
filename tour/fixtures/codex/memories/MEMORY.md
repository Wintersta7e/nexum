# synthetic memories — codex tour fixture

The Codex adapter parses `## Task <label>` H2 sections; everything else
is ignored. This fixture exists only so the tour has well-formed records
to ingest. It does not describe any real work item.

## Task tour-smoke-codex
Run a single ingestion + read pass against this file inside the tour
container. The adapter should produce one record with the slug
`tour-smoke-codex` and treat the H2 body as the record's content.

## Task tour-empty-source-handling
Cover the path where the adapter reports `ingested >= 1` with
`completeness = authoritative` against this synthetic input. No host
state is referenced; the container's `/root/.codex/` is bind-mounted
read-only.
