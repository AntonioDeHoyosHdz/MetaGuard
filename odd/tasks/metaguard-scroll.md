# MetaGuard — scroll-driven image sequence

Branch: `feat/frontend-visual` · Delivery: `stacked-to-main` · Tests: `npm test`, `tsc --noEmit`; no build.

## Specs

- S1: «También quiero que mejoren el diseño de front. No, no está sustando como eso de JavaScript que usas para hacer ese cubo. Me interesa mejor que genera, descarga un prompt de imágenes para reproducir imágenes, un skill y genera imágenes, así como por fotogramas. O sea, genera como, es un ejemplo, como 20 imágenes y que mientras vayamos scrollingeando se van secuenciando para que tengas la forma, pues de que se está moviendo, que está interactuando o que pasa algo con alguna interacción, pero que sea como una imagen o algo así relacionado, pues con de lo que hablamos, que quede bonito, como el ejemplo que te había mandado.»
- S2: «Never build after changes.» Preserve the existing synthetic demo, accessibility, mobile support and reduced-motion behavior; never suggest that real upload or cleaning works.
- S3: Use original generated imagery rather than the reference website's assets or brand. A 20-frame sprite sheet is an implementation choice to reduce requests and keep frames consistent.

## Tasks

- T1 (S1, S3): Generate an original coherent 20-frame privacy-themed image sequence; route: image tool; status: complete.
- T2 (S1–S3): Replace the procedural 3D cube with scroll-driven frames; route: inline; status: complete; commit: pending.
- T3 (S1–S3): Verify scroll behavior, reduced motion, desktop/mobile and existing tests without build; route: inline + independent verifier; status: complete.

## Log

- L1: «que mas falta  quiero que También quiero que mejoren el diseño de front. No, no está sustando como eso de JavaScript que usas para hacer ese cubo. Me interesa mejor que genera, descarga un prompt de imágenes para reproducir imágenes, un skill y genera imágenes, así como por fotogramas. O sea, genera como, es un ejemplo, como 20 imágenes y que mientras vayamos scrollingeando se van secuenciando para que tengas la forma, pues de que se está moviendo, que está interactuando o que pasa algo con alguna interacción, pero que sea como una imagen o algo así relacionado, pues con de lo que hablamos, que quede bonito, como el ejemplo que te había mandado.»
- Used the installed `imagegen` skill and built-in image tool to generate an original 5×4 sprite sheet. The sheet depicts a translucent vault, document and halo; it does not reuse the reference site's model or artwork.
- Replaced Three.js with one local 20-frame PNG sheet (1,909,790 bytes); scrolling selects frames and reduced motion uses the first still. A local SVG appears if the sheet fails to load. The existing demo remains synthetic.
- RED: new frame tests failed against the old 3D scene. GREEN: 8 frontend tests and `tsc --noEmit` passed. An independent scratch verifier checked scrolling, mobile mapping, live reduced-motion changes, fallback, cleanup and dependency/lock consistency; no blockers. `npm ls --package-lock-only --all --json` showed six optional Tailwind WASM diagnostics on both baseline and candidate.
- Local development preview inspected at 1258×622 and 390×844; desktop scroll changed the selected sprite frame, mobile mapping was corrected to advance while the illustration is visible, and reduced-motion emulation remained on frame zero. No build was run. Full accessibility, real-device performance and image-transfer optimization remain pending.
