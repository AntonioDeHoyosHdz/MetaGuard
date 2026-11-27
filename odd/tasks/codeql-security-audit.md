# CodeQL first security assessment

Branch: `feat/frontend-visual` · Delivery: existing feature branch · Runner: CodeQL CLI with no-build extraction; backend pytest and frontend tests where applicable.

## Specs

- S1: «Detecta vulnerabilidades en todo un código fuente con CodeQL»; analyze the project's supported first-party Python and JavaScript/TypeScript source without building the application.
- S2: «Crea una consulta para localizar todas las variantes de una vulnerabilidad y elimínala por completo. Después, comparte tu consulta para ayudar a otros a hacer lo mismo.» Validate any finding before fixing; do not claim complete elimination beyond the demonstrated query and its coverage.
- S3: «Ejecuta una primer prueba a tu proyecto, ya sea Web o Movil. Y genera un reporte.» Describe tool choice, scope, results, fixes and limitations without secrets.
- S4: «Never build after changes.» Preserve existing uncommitted work and do not use a real database, Docker, remote deployment or credentials.

## Tasks

- T1 (S1, S3, S4): Run source-only CodeQL no-build extraction and security suites for available languages in private scratch; route: inline; status: complete for first-party Python and JS/TS snapshot; commit: 44297c6. Risk: item 5 (external tooling).
- T2 (S2, S4): Fix the independently reproduced `/PieceInfo` private-metadata leak in PDFs, verify catalog/page and direct/indirect/string/stream variants, and create a bounded reusable policy query; route: inline with independent security verification; status: implemented and independently checked; commit: 44297c6. Risk: item 2 (privacy/security).
- T3 (S1–S4): Produce a truthful security report and document uncovered scope and remaining risks; route: inline; status: report written; commit: 44297c6. Risk: none (documentation).

## Log

- L1 [2026-11-17]: «Detecta vulnerabilidades en todo un código fuente con CodeQL, el motor de análisis semántico de código te permite realizar consultas sobre el código como si se tratara de datos. Crea una consulta para localizar todas las variantes de una vulnerabilidad y elimínala por completo. Después, comparte tu consulta para ayudar a otros a hacer lo mismo.\
\
CodeQL es gratuito para fines de investigación y para proyectos de código abierto.\
\
Mobile Security Framework (MobSF) es un framework automatizado e integral para realizar pruebas de penetración, análisis de malware y evaluaciones de seguridad en aplicaciones móviles (Android/iOS/Windows), capaz de llevar a cabo análisis tanto estáticos como dinámicos.\
\
\
Ejecuta una primer prueba a tu proyecto, ya sea Web o Movil. Y genera un reporte.»
- Existing worktree includes a prior unrelated modification to `docs/backend-persistencia.md` and the T3j tracker update; preserve both. Engram mirror pending because the runtime has no authoritative registered session ID.
- L2 [2026-11-17]: CodeQL 2.27.4 analyzed a tracked source-only snapshot: 71/71 Python files and 8/8 JavaScript/TypeScript files extracted, using `--build-mode=none` and the local security-extended suites. Python reported 11 `py/weak-sensitive-data-hashing` alerts: one HIBP protocol SHA-1 calculation and ten synthetic tests; JavaScript reported zero alerts. The HIBP use requires SHA-1 for its documented range protocol and is not password storage. A separate independent manual review reproduced a real `/PieceInfo` PDF privacy leak in eight synthetic variants; it was NOT reported by CodeQL's standard suite. T2 is the explicit correction. Raw databases and SARIF are in local scratch and are not to be committed or published.
- L3 [2026-11-17]: Added `/PieceInfo` removal, rejection of retained indirect private aliases and trailer coverage. Custom query results: 1 alert on baseline, 1 on an intermediate version, 0 on the final analyzed snapshot; this is a bounded structural heuristic, not proof of complete vulnerability removal. Independent verification covered alias and trailer cases. Backend: 361 passed, 6 PostgreSQL opt-in tests skipped; frontend: 12 passed; Ruff checks passed. Post-fix standard Python suite rerun failed because its database lacked the dbscheme; initial standard suite and final custom-query results succeeded. No application build was run. Report: `docs/reporte-seguridad-codeql.md`; query: `security/codeql/python/pdf-pieceinfo-policy.ql`. Raw databases and SARIF remain private in temporary storage.
- L4 [2026-11-17]: Delivered the security work unit in `44297c6`. Receipt-driven development is disabled globally; no native review was claimed. Engram mirror remains pending because runtime registration is unavailable.
