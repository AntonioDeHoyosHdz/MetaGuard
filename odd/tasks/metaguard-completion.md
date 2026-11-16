# MetaGuard — complete the application

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: backend pytest and frontend npm test; no build.

## Specs

- S1: «hazlo ectar cuentas y base de datos real, procesar y limpiar archivos de forma aislada, integrar el front con la API y preparar el despliegue. La purga de caché ya tiene un comando, pero todavía no está programada.»
- S2: «Never build after changes.» Do not use an existing database, credentials or a remote deployment without the specific authorization required for that destination and operation.
- S3: Preserve the proposal's authentication, MFA, CSRF, object authorization, file-processing isolation, retention and privacy requirements; do not present simulations as real processing.
- S4: «todas las llaves, todo lo importante en el .gitignore para que no se filtre nada». Exclude machine-specific local agent and memory state from ordinary Git additions while verifying that application source is not accidentally ignored; ignore rules do not block force-adds or protect already-tracked history.

## Tasks

- T1 (S1–S3): Implement a schedulable reputation-cache purge worker with safe failures and tests; route: inline; status: complete; commit: `a681471`. Risk: item 1 (persisted data deletion), item 4 (timing), item 5 (runtime). Deployment and monitoring remain pending under T5.
- T2 (S1–S3): Implement account persistence and authentication with database migrations and tests; route: inline unless a named writer trigger applies; status: in progress; commit: pending. Risk: items 1–3.
- T2a (S1–S3): Pin and restore approved account-security dependencies without builds; route: delegated install + independent verifier; status: complete; commit: `4627bf6`. Risk: item 5 (dependencies).
- T2b (S1–S3): Implement and verify account credential primitives and persistence without exposing incomplete authentication; route: inline; status: in progress; commit: pending. Risk: items 1–3.
- T2b1 (S1–S3): Add internal password hashing primitives and tests; route: inline with independent security verification; status: complete; commit: `66240a4`. Risk: item 2 (credentials).
- T2b2 (S1–S3): Add account persistence without exposing incomplete authentication; route: inline; status: complete for initial schema only; commit: `e333da2`. Risk: items 1–3.
- T2c (S1–S3): Add internal authenticated encryption for TOTP secrets, bound to account identity; route: inline and independent security verification; status: complete; commit: `d09a014`. Risk: item 2.
- T2d (S1–S3): Persist encrypted TOTP credentials, key version and last accepted time step in a separate account-owned table; no authentication endpoints; route: inline with independent verification; status: complete for schema only; commit: `1c5d325`. Risk: items 1, 2 and 4.
- T2e (S1–S3): Verify a TOTP code and atomically consume its time step inside the caller transaction; route: inline and independent security verification; status: complete for internal primitive; commit: `ae448c2`. Risk: items 2 and 4.
- T2f (S1–S3): Prepare an isolated pending TOTP enrollment record with explicit expiry; no routes or activation without confirmation; route: inline with independent security verification; status: complete for staging only; commit: `8607231`. Risk: items 1, 2 and 4.
- T2g (S1–S3): Remove expired pending TOTP enrollment for a specific account without affecting active or unexpired credentials; route: inline with independent security verification; status: complete for internal operation; commit: `116e2cd`. Risk: items 1, 2 and 4.
- T2h (S1–S3): Confirm pending TOTP with an unexpired code and activate atomically under account-level serialization; route: inline and independent verification; status: complete for internal primitive; commit: `4939518`. Risk: items 1, 2 and 4.
- T2l (S1–S3): Use SQL RETURNING instead of driver-dependent rowcount for pending/active TOTP inserts; route: inline with independent security verification; status: complete; commit: `e84e61a`. Risk: items 2 and 4.
- T5a (S1–S3): Verify all current Alembic migrations and TOTP flows against a fresh disposable PostgreSQL 16 instance; route: inline; status: complete for local DB verification; commit: `e84e61a`. Risk: items 1, 2 and 4.
- T2m (S2, S4): Ignore local `.atl/` skill-index and `.engram/` memory metadata from ordinary Git candidate selection to reduce accidental exposure of machine-specific paths/configuration; route: inline; status: complete; commit: pending. Risk: item 2 (local configuration/path exposure).
- T2i (S1–S3): Implement password screening with breached-password lookup and explicit local fallback, without exposing incomplete registration; route: inline with independent security verification; status: complete for internal primitive; commit: `39bae76`. Risk: item 2.
- T2j (S1–S3): Persist minimized service-security events with 30-day retention support for password-screening outages; route: inline with independent security verification; status: complete for internal store; commit: `75397f6`. Risk: items 1, 2 and 4.
- T2k (S1–S3): Schedule security-event retention in the existing maintenance loop with an atomic shared transaction; route: inline with independent verification; status: complete for local schedule; commit: `9bfbc3f`. Risk: items 1, 4 and 5.
- T3 (S1–S3): Implement isolated file processing, cleanup and verification; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 1–5.
- T4 (S1–S3): Connect the frontend to real API workflows with honest error states; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 2–3.
- T4a (S1–S3): Connect the visual frontend to the real API liveness endpoint with honest, accessible error states and no file processing claims; route: inline with independent environment verification; status: complete for liveness only; commit: `c386b44`. Risk: items 3 and 5.
- T5 (S1–S3): Prepare a reproducible, cost-conscious deployment and verify it in an authorized environment; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 2, 5.

## Log

- L1: «hazlo ectar cuentas y base de datos real, procesar y limpiar archivos de forma aislada, integrar el front con la API y preparar el despliegue. La purga de caché ya tiene un comando, pero todavía no está programada.»
- L2: «a revisión nativa sigue bloqueada: pronóstico parcial, paso 1, tipo `collect`, motivo `intended_untracked_selection_required`; requiere seleccionar archivos sin seguimiento. La revisión independiente sí se realizó, pero no r   hazlso y sihgue»
- Existing code has a PostgreSQL helper, a readiness check, a reputation-cache table and a one-shot purge; no account tables, authentication, real upload/cleaning or connected frontend. PostgreSQL real, worker isolation and deployment are not yet verified.
- Existing project documentation leaves MFA/recovery, API–worker IPC/key transfer and several account-policy details unresolved. Preserve those boundaries; do not silently bypass MFA or parse hostile files in the networked API.
- Previous confirmed `stacked-to-main` strategy applies. Estimate: more than 400 authored lines across the complete feature; keep coherent work units with tests and docs.
- T1 RED: scheduler tests failed before implementation. GREEN: 74 backend tests, Ruff and format checks passed. Independent verification reproduced a SIGTERM deadlock in the first candidate; a lock-free stop flag and bounded monotonic sleeps fixed it. Targeted recheck with a real signal exited in about one second; a regression test was added. No build or live database was used.
- `schedule-reputation` retries failed purges at a configured interval and stops on SIGTERM, but it is not running or supervised until deployment. Delays or downtime can exceed 24-hour physical retention, so the retention requirement remains unverified.
- Commit `a681471` was pushed after Gitleaks reported no leaks. Native assessment was high; native review could not start because its untracked-file selection capture was unavailable. The independent verifier's result is not a native approval.
- T2 preparation: the backend environment lacks the Argon2, AES-GCM, JWT and TOTP libraries needed for the documented account/security design. Do not substitute homegrown cryptography or import undeclared global packages. Anonymous downloads of new packages require explicit authorization; actual account fields, MFA and recovery remain incomplete.
- User authorized anonymous downloads from `pypi.org` and `files.pythonhosted.org` for `argon2-cffi`, `cryptography`, `PyJWT`, `pyotp` and their required dependencies, using prebuilt packages and no builds. Record exact resolved versions in the existing lockfile before implementation.
- T2a: installed and pinned `argon2-cffi 25.1.0`, `cryptography 50.0.2`, `PyJWT 2.15.1` and `pyotp 2.11.2`. Independent verification found only approved PyPI artifact hosts and matching lock hashes; baseline and candidate each passed 74 tests. Primitive smoke tests were added; the current backend suite passes 77 tests. No account, token, MFA or recovery flow is implied by the libraries alone.
- T2a commit `4627bf6` was pushed. Native assessment was high; review could not start because the required untracked-file selection capture was unavailable. Independent checks are not a native approval.

- T2b1: Added Argon2id credential hashing and strict bounded PHC parsing. Initial focused tests were RED before implementation; an independent verifier reproduced malformed Unicode and embedded-NUL defects, which were pinned with failing tests before correction. Fixed parameters require a future rehash migration strategy. Account persistence and authentication remain pending.
- T2b1 verification: 84 backend tests and Ruff passed; the independent verifier confirmed both malformed-Unicode and embedded-NUL regressions were fixed. No build or live database was used. Engram mirror pending because the runtime session identity was not registered.
- User confirmed: «si» — use the email address as account identifier and for account recovery. Registration, recovery, MFA, and real PostgreSQL verification are still pending. Initial schema stores the email in plaintext; database access restrictions and encryption-at-rest remain deployment requirements, not implemented protections.

- T2b2: Added an initial accounts table migration with unique lowercase email and password hash columns, without exposing registration or login. Email normalization policy, verification, recovery, MFA, encryption at rest and real PostgreSQL verification remain pending. The SQLite migration test was RED before the migration and GREEN after it; independent security verification is pending.

- Independent verifier found no blockers in schema-only scope: tested migration and prior cache preservation, 13 focused tests passed, and PostgreSQL SQL generated offline. SQLite lower() does not normalize all Unicode. Downgrade deletes account rows; no live database was touched. Full backend suite: 86 passed; Ruff passed. Engram mirror remains pending due to unregistered runtime session.
- Documentation correction: synchronized the README and persistence guide with the actual image sequence, migrations, test evidence, and still-disconnected frontend.

- User requested: «Ejecuta todo lo que te hace falta entonces ponte en modo cualy y termina todo lo que te hace falta todo lo que acabamos de hablar.» T2c is a prerequisite only; no MFA or login endpoint is enabled. Engram mirror remains pending because session identity is not registered.

- T2c: RED observed before implementation; 93 backend tests and Ruff passed. Independent verifier checked 117 malformed or tampered cases, 1,000 sampled nonces, account binding and unchanged API routes; no blockers. Key rotation, secret storage and MFA integration remain pending.

- User request: «sigue los passoso de odd , y haz todos los folojs y todo loq eu te gacerf calt a». T2d prepares MFA persistence; no enrollment, login or replay protection is claimed until its transactional verification flow is implemented. Engram mirror remains pending: runtime session identity not registered.

- T2d: RED reproduced before migration; 95 backend tests and Ruff passed. Independent verification passed migration, constraints, prior-data preservation, cascade and offline PostgreSQL SQL; no live PostgreSQL was used. Schema alone cannot enforce encrypted contents or prevent TOTP replay.

- User request: «hazlos entonces». T2e is an internal building block; registration, enrollment, login, lockout and recovery remain pending. The Engram mirror is pending due to an unregistered runtime session.

- T2e: observed RED before implementation, then 100 backend tests and Ruff passed. Independent verification observed one committed success in each of 16 SQLite races, rollback and credential-replacement checks. Caller must commit before granting access. PostgreSQL concurrency, API, rate limits and enrollment remain unverified or absent.

- User request: «dived etodo por pasaos y mientras vayas avanzando sigue cin el sigueutne ya no mr erpegunte se supone que paraeso esta el odd». Continue authorized units without unnecessary prompts. Pending MFA setup must remain separate from active credentials; expiry is caller-supplied and not a product policy decision. Engram mirror remains unavailable because runtime session identity is unregistered.

- T2f: RED before implementation; 103 backend tests and Ruff passed. Independent staging verifier observed one winner in 16 SQLite races and validated rollback, account-bound ciphertext and offline PostgreSQL SQL. No confirmation, active MFA, cleanup or live PostgreSQL exists. Cross-table enrollment and activation require shared account-level serialization.

- User request: «siguele». T2g removes only expired pending enrollment inside caller-owned transaction; activation remains separate. Engram mirror is pending because runtime session identity is not registered.

- T2g: RED then GREEN; 109 backend tests and Ruff passed. Independent SQLite probes covered 16 double-deletion and 16 replacement races, rollback, account isolation and active credential preservation. PostgreSQL concurrency and scheduled execution remain unverified.

- User request: «siguele apruebo todo». Proceed within authorized scope without claiming unspecified external access or fabricating runtime session identity. T2h is an internal service, not public authentication.

- T2h: RED before implementation; verifier exposed partial activation if deletion failed and the caller committed. Added a savepoint, verified abort and ignore failures with regression tests, and reran independent targeted checks including 64 SQLite races. Full suite 113 passed; Ruff passed. Account lock is a no-op update and can alter physical storage even on rejected operations. No live PostgreSQL, login, authorization, rate limiting or endpoint verification.

- User request: «hazklo odavía faltan el registro y acceso públicos, la prueba en PostgreSQL real, el procesamiento de archivos y la integración del frontend. La revisión nativa sigue pendiente: pronóstico parcial, paso 1, tipo `collect`, motivo  pues». T4a connects only liveness, not authentication or file processing. The external review-selection capture operation is not exposed. Engram runtime session remains unregistered.

- T4a: observed failing tests before implementation. A live local Vite-to-FastAPI liveness request returned HTTP 200 and {"status":"ok"}; no database or user file used. Independent reviewer found contrast, mobile layout and broad proxy issues; corrected and rechecked. Preview does not inherit the local API proxy. Authentication, uploads, processing and deployment remain pending.

- User objective: «corrijelo y  no apres hasta que lo corrija sy sugue eoy tmeirna con el proeycto». The review provider still returns a required `external.select_intended_untracked` capture unavailable in this runtime; no selection is fabricated. T2i develops the registration password-screening prerequisite. Conservative provisional minimum: 15 Unicode code points, not a claim of MFA being enabled. Engram mirror remains unavailable due to unregistered runtime session.

- T2i: RED then GREEN; independent verifier found malformed responses could mask a known breach, plus oversized counts; both now report the generic outage and reject. True service outages allow explicitly reduced fallback only when a caller-supplied nonempty local blocklist and event callback succeed. 120 backend tests and Ruff passed. The maintained list, persistent event integration and public registration remain missing.

- T2j: provide a persistent, allowlisted system-event store and retention operation needed by the documented password-check outage fallback. No endpoint or scheduled retention is implied; account-linked audit and production PostgreSQL verification remain pending. Engram mirror pending: runtime identity unavailable.

- T2j: observed RED then GREEN; 130 backend tests and Ruff passed. Independent verifier checked migration, existing-data preservation, 30-day cutoff and SQLite races. Added separately committed outage reporting after proving a shared account transaction could lose the audit on rollback; recheck passed. SQLite lock requires screening before account writes. No scheduler, public registration or live PostgreSQL verification is claimed.

- User request resumed the full project. T2k extends existing periodic maintenance to events without a separate unsupervised scheduler; tests prove atomic retention only, not deployed supervision.

- T2k verification note: an independent review caught a compatibility regression when the old cache-only command began requiring the new events table and changed output. Kept its legacy scope/output; added a separate atomic `purge-maintenance` command, used by the scheduler.

- T2k GREEN: 133 backend tests and Ruff passed. Independent verifier confirmed legacy `purge-reputation` output and behavior unchanged; `purge-maintenance` and scheduled maintenance share an atomic transaction; cutoff, rollback, error privacy, cadence and SIGTERM passed SQLite checks. Production PostgreSQL and deployed supervision remain unverified. Risk: item 1 (retention deletion), item 4 (scheduler/concurrency), item 5 (runtime).

- T2l discovery: a disposable PostgreSQL 16 run showed the INSERT side effect succeeded while the psycopg rowcount-based helper reported False. Both staging and activation now use `RETURNING` to distinguish insert from conflict. The same local PostgreSQL run confirmed staging, activation, replay rejection and one winner among two concurrent same-step verifiers.
- T5a: `alembic upgrade head`, `alembic check`, `downgrade base`, `upgrade head`, `alembic check` all passed against ephemeral PostgreSQL 16.13. Account/TOTP insert and two-session concurrency passed; maintenance deleted only the expired event. This is disposable local verification, not production connectivity or deployment.
- Added an opt-in PostgreSQL integration regression test guarded to a loopback host and database named exactly `metaguard_test`. Against the baseline commit, it failed at pending TOTP staging (RED); on the candidate it passed (GREEN). The usual suite passed 133 tests with this opt-in test skipped; Ruff passed. The ephemeral baseline worktree was removed after verifying its path.
- The prior native candidate terminated with `retry_safe:false` and `next_action:stop`; that did not grant approval. After the candidate's local tool state was excluded, a fresh status found no eligible untracked files. Risk assessment for `e84e61a` against `9bfbc3f` returned `medium` / `under_budget`; no review was started or approval claimed.
- T2m: inspection found the untracked `.atl/skill-registry.md` contains absolute Windows paths, while `.atl/.skill-registry.cache.json` and `.engram/config.json` are local tool state; none were tracked. Added root ignore rules. `git check-ignore -v` matched all three paths and `git ls-files --others --exclude-standard` became empty. Ignore rules do not prevent force-adds or protect already-tracked history, so staged scans remain required. Risk: item 2 (reduce accidental exposure of user-specific local configuration/path metadata).
