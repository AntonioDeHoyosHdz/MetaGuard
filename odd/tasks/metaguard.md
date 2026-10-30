# ODD — MetaGuard

## Objetivo
Avanzar el proyecto MetaGuard conforme a la propuesta U2 y al prompt operativo del usuario, conservando evidencia verificable y esperando confirmación antes de iniciar una fase nueva.

## Alcance actual — Fase 0: explorar
- [x] Localizar y leer la propuesta PDF U2.
- [x] Extraer texto de la propuesta a `docs/propuesta-u2.txt`.
- [x] Inventariar repositorio y contrastar OBJ-01 a OBJ-07 y sus medidas de éxito.
- [x] Registrar módulos, estado de datos y huecos/preguntas en los documentos de fase 0.
- [x] Verificar versiones/herramientas locales disponibles.
- [ ] Presentar reporte al usuario y esperar confirmación antes de Fase 1.

## Evidencia
- `docs/propuesta-u2.txt`: texto extraído localmente de 19 páginas con pypdf; 28,580 caracteres.
- `docs/trazabilidad.md`: tabla de objetivos/criterios, módulos y modelo de datos.
- `docs/avance/fase-0.md`: hallazgos, preguntas abiertas y límites de la revisión.
- `docs/propuesta-u2.txt` se generó con `uv run --with pypdf python ...`; el paquete se ejecutó mediante `uv`.
- Repositorio Git local inicializado en `main`; commit inicial `5fb8e13` (`Add MetaGuard project files`). `.codex/` y el checkout no relacionado `gentle-ai/` se excluyeron del repositorio.

## Estado
- Fase 0: completada para este inventario local; 0% verificado para cada OBJ-01…OBJ-07. No se modificó código.
- El repositorio local ya está listo; creación del remoto y subida están en curso.
- Siguiente paso: únicamente tras confirmación expresa del usuario, iniciar Fase 1.

