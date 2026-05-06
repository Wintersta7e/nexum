# synthetic memories — codex e2e fixture

The codex adapter parses `## Task <label>` H2 sections; everything else is
ignored. This fixture exists only so the e2e harness has well-formed records
to ingest. It does not describe any real work item.

## Task harness-empty-source-handling
Verify the adapter reports `ingested=0` with `completeness=authoritative` when
the memories dir contains zero records. This task is a placeholder for the
adapter's empty-source path.

### keywords
empty-source, completeness, authoritative

## Task harness-ingest-roundtrip
Verify a single record roundtrips through the adapter discover-and-read flow,
gets committed by the local-adapter pass, and surfaces in the read verbs.

### keywords
roundtrip, adapter, discover, read
