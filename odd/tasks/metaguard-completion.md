# MetaGuard — complete the application

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: backend pytest and frontend npm test; no build.

## Specs

- S1: «hazlo ectar cuentas y base de datos real, procesar y limpiar archivos de forma aislada, integrar el front con la API y preparar el despliegue. La purga de caché ya tiene un comando, pero todavía no está programada.»
- S2: «Never build after changes.» Do not use an existing database, credentials or a remote deployment without the specific authorization required for that destination and operation.
- S3: Preserve the proposal's authentication, MFA, CSRF, object authorization, file-processing isolation, retention and privacy requirements; do not present simulations as real processing.

## Tasks

- T1 (S1–S3): Implement a schedulable reputation-cache purge worker with safe failures and tests; route: inline; status: complete; commit: `a681471`. Risk: item 1 (persisted data deletion), item 4 (timing), item 5 (runtime). Deployment and monitoring remain pending under T5.
- T2 (S1–S3): Implement account persistence and authentication with database migrations and tests; route: inline unless a named writer trigger applies; status: in progress; commit: pending. Risk: items 1–3.
- T2a (S1–S3): Pin and restore approved account-security dependencies without builds; route: delegated install + independent verifier; status: complete; commit: `4627bf6`. Risk: item 5 (dependencies).
- T2b (S1–S3): Implement and verify account credential primitives and persistence without exposing incomplete authentication; route: inline; status: in progress; commit: pending. Risk: items 1–3.
- T2b1 (S1–S3): Add internal password hashing primitives and tests; route: inline with independent security verification; status: complete; commit: pending. Risk: item 2 (credentials).
- T2b2 (S1–S3): Add account persistence without exposing incomplete authentication; route: inline; status: pending; commit: pending. Risk: items 1–3.
- T3 (S1–S3): Implement isolated file processing, cleanup and verification; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 1–5.
- T4 (S1–S3): Connect the frontend to real API workflows with honest error states; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 2–3.
- T5 (S1–S3): Prepare a reproducible, cost-conscious deployment and verify it in an authorized environment; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 2, 5.

## Log

- L1: «hazlo ectar cuentas y base de datos real, procesar y limpiar archivos de forma aislada, integrar el front con la API y preparar el despliegue. La purga de caché ya tiene un comando, pero todavía no está programada.»
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
