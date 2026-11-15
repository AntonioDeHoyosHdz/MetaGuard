# MetaGuard — complete the application

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: backend pytest and frontend npm test; no build.

## Specs

- S1: «hazlo ectar cuentas y base de datos real, procesar y limpiar archivos de forma aislada, integrar el front con la API y preparar el despliegue. La purga de caché ya tiene un comando, pero todavía no está programada.»
- S2: «Never build after changes.» Do not use an existing database, credentials or a remote deployment without the specific authorization required for that destination and operation.
- S3: Preserve the proposal's authentication, MFA, CSRF, object authorization, file-processing isolation, retention and privacy requirements; do not present simulations as real processing.

## Tasks

- T1 (S1–S3): Implement a schedulable reputation-cache purge worker with safe failures and tests; route: inline; status: complete; commit: pending. Risk: item 1 (persisted data deletion), item 4 (timing), item 5 (runtime). Deployment and monitoring remain pending under T5.
- T2 (S1–S3): Implement account persistence and authentication with database migrations and tests; route: inline unless a named writer trigger applies; status: pending; commit: pending. Risk: items 1–3.
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
