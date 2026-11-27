# MetaGuard — reputation cache

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: backend pytest; no build.

## Specs

- S1: «siguele» — continue MetaGuard implementation. U2 requires a reputation cache with hash/verdict only, no user link, 24-hour retention and purge (`docs/propuesta-u2.txt`, `docs/datos.md`).
- S2: «Never build after changes.» No network calls or migration against an existing database are authorized by this task.
- Assumption: cache an explicit coarse verdict (`malicious`, `suspicious`, `undetected`, `no_record`), not raw provider responses or file content; `undetected` does not mean safe. A future VirusTotal client must map its results explicitly and obtain consent.

## Tasks

- T1 (S1): Map existing database and cache contract; route: read-only explorer; status: complete.
- T2 (S1–S2): Add cache model, reversible migration, bounded read/write and expiration purge with tests; route: inline; status: complete; commit: `eaf578c`. Risk: item 1 (persisted schema), item 4 (concurrent upsert).
- T3 (S1–S2): Run SQLite/offline SQL checks and independent verification; document real PostgreSQL and scheduled purge as pending; route: inline + independent verifier; status: complete.
- T4 (S1–S2): Provide a one-shot maintenance command that purges expired cache rows within a transaction, with safe errors and isolated tests; route: inline; status: complete; commit: `a2064ad`. Risk: item 1 (deletion of persisted cache data).

## Log

- L1: «siguele»
- The existing Alembic metadata has no business tables. This unit is an internal persistence component, not a VirusTotal integration or a deployed database. PostgreSQL live verification was previously blocked by execution policy and remains unverified.
- The reference service publishes analysis categories and separately represents undetected versus lack of a record: https://docs.virustotal.com/reference/files. Cache entries must not contain raw service payloads, filenames, user identifiers or file bytes.
- RED: cache tests initially failed because the module did not exist. GREEN: 63 backend tests, Ruff and format checks passed. Independent scratch verification passed SQLite migration and rollback, expiry/purge boundary, invalid-write invariants, ten concurrent stale/new writes, and offline PostgreSQL SQL compilation; no live PostgreSQL was contacted. No build was run.
- Expired entries are excluded from reads but remain physically stored until `purge_expired` is called in a committed transaction. Scheduled purge, provider integration, consent and real PostgreSQL verification remain pending. SQLite direct SQL does not enforce binary typing; the supported API writes 32-byte digests and PostgreSQL uses BYTEA.
- Commit `eaf578c` was pushed after the staged secret scan reported no leaks. Native review assessed high risk but could not start because its untracked-file selection capture was unavailable; independent verification is not a native approval.
- User continuation: «siguele». A maintenance command is a prerequisite to scheduled deletion; a scheduler, a live PostgreSQL test and deployment remain separate pending work.
- T4: 67 backend tests and Ruff passed; independent scratch verification confirmed cutoff, commit, rollback, generic errors and engine disposal. No build or live database access. The command must be scheduled and monitored before physical 24-hour deletion can be claimed.
- Commit `a2064ad` was pushed. Native review assessed high risk but could not start because its untracked-file selection capture was unavailable; the independent verification is not a native approval.
