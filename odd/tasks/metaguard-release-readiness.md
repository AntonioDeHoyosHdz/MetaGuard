# MetaGuard local release readiness

Branch: feat/frontend-visual. Delivery: working tree only, no commit, build, push, or public deployment.
Verification: pytest, Ruff, Vitest, TypeScript; synthetic fixtures only unless separately approved.

## Specs

- S1. "completa tood loq eu ahce flata porfa": continue from the preceding audit. Correct clean download extensions without using original names.
- S2. Complete the recovery path for undelivered or expired registration email: explicitly request a new verification code, preserve MFA and existing account flows, expose no account-existence signal in the ordinary response.
- S3. Reconcile the current-state API, development, privacy and U2 evidence documentation. Preserve historical checkpoints; do not sign off privacy, deploy publicly or access provider accounts.
- S4. Make the professor's local demonstration easier to reproduce and distinguish any unverified U2 or production requirements.

## Tasks

- [x] T1 (S1) — MIME-safe filenames, regression tests; inline at shared frontend seam.
- [x] T2 (S2) — defensive account verification resend and frontend; delegated backend, parent integration, independent verification. Risk: item 2 (account and credential protections); item 4 (token rotation).
- [x] T3 (S3–S4) — current-state documentation and academic demonstration guide; delegated docs and parent proof.
- [ ] T4 (S2–S4) — authenticated password change verified; anonymous reset, deletion, activity/notifications, complete U2 evidence and staging remain open. Risk: items 2 and 4 (credential and session state).

## Log

- L1. "completa tood loq eu ahce flata porfa"
- The existing demo has previously used synthetic Gmail/VT provider controls, but no real provider activation or public deployment is authorized by this follow-up. The existing working tree is intentionally left uncommitted.
- [2026-11-21] T1 and T2 delivered: fixed MIME-derived clean filenames; generic password-gated verification resend with throttles, atomic token replacement, and a standalone PostgreSQL 17.6/loopback SMTP run. T4 also advances: authenticated password change, atomic session and challenge revocation (preserving TOTP and recovery codes), and browser revalidation if the request returns 401. Independent recheck initially could not start its fixture under contention; the final serial frontend suite, including the 401 regression, passed. Synthetic PostgreSQL confirmed real routes and subsequent old/new login; concurrent PostgreSQL ordering was not exercised by the smoke. Final suites: 556 backend passed with 6 opt-in integration tests skipped, 89.02% coverage; 70 frontend passed in serial, plus TypeScript and Ruff lint/format. No build, provider call, demo restart, commit or push.
- [2026-11-21] T3 delivered: local setup, API, data, secrets, account recovery, architecture, persistence, processing, costs, limits and academic guide reconciled. Documentation checks covered local links, a synthetic sample and diagram references. The definitive privacy notice and deployment are deliberately unchanged; the browser test used an adapter, not the production-like separated-UID Unix socket.
