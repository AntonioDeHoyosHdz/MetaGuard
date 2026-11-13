# MetaGuard — immersive frontend

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: `npm test` (no build).

## Specs

- S1: «lo puedes ahcer como este busca una skilsl que te ayude a extrar y sacar la referencia d eocmo lo hizo uy hazo aora enuesto oroyecto» — adapt the visual experience of https://codeofsagar.in/ to MetaGuard with original assets, preserving the existing demo and accessibility behavior.
- S2: «Never build after changes.» Preserve the local-only demonstration: no real file upload or claims of real processing.

## Tasks

- T1 (S1): Inspect the visual reference and existing frontend; route: read-only explorer + inline; status: complete.
- T2 (S1–S2): Implement the cinematic hero and cohesive responsive styling; route: inline; status: complete; commit: pending.
- T3 (S1–S2): Run available tests and visual checks without a build; document limitations; route: inline; status: complete.

## Log

- L1: «[https://codeofsagar.in/](https://codeofsagar.in/) lo puedes ahcer como este busca una skilsl que te ayude a extrar y sacar la referencia d eocmo lo hizo uy hazo aora enuesto oroyecto»
- Reference observed: full-screen atmospheric 3D scene, soft sky palette, oversized typography, and scroll-led composition. Do not copy the reference's model, images, branding, or text. Existing MetaGuard scene already has WebGL fallback and reduced-motion behavior.
- Existing `agent-browser` was used to inspect the site. Candidate skill: https://github.com/Paidax01/web-to-design-md/blob/main/SKILL.md; not installed or executed. Existing frontend tests enforce a synthetic demo without file uploads.
- The first implementation adds an atmospheric full-height hero and an original orbital detail to the existing 3D scene; it is not yet visually verified. `git diff --check` passed. Offline `npm ci --offline --ignore-scripts --no-audit --no-fund` failed on an uncached package; Vitest and Vite are unavailable, so tests and a local preview remain pending. No build was run.
- Independent static review identified repeating background gradients, low-contrast keyboard focus, and a low-contrast WebGL fallback. The three source-level findings were corrected and independently rechecked; browser and automated tests remain pending.
- With user authorization, restored locked npm dependencies using `npm ci --ignore-scripts --no-audit --no-fund`. `npm test`: 5 tests passed; `tsc --noEmit` and `git diff --check` passed. Inspected the local development view at 1258×622 and 390×844; the mobile menu opened and closed with Escape. The first desktop inspection exposed a headline wrapping problem; adjusted its size and rechecked. No build was run. Screen-reader, exhaustive contrast and device testing remain pending.
