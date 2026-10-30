# Fase 1 — Documentación base

Fecha: 30 de octubre de 2026. Plan aprobado por el usuario; documentación entregada en una cadena de PRs apilados. Los cambios aún no están integrados a `main`.

## Hecho y evidencia

- 12/12 documentos planeados redactados: arquitectura, flujo, STRIDE, datos, riesgo de metadatos, límites, API, llaves, recuperación, corpus, aviso de privacidad y plan de trabajo.
- OBJ-01: diagrama Mermaid con cinco límites de confianza; cinco pasos de carga/retención; matriz con 14 amenazas STRIDE y controles/pruebas previstos.
- OBJ-02: contrato con 18 rutas; autenticación/CSRF/propiedad, tasas candidatas, respuestas de error y requisitos de OpenAPI anotados.
- Datos U2 §3.2 preservados. Números de límites, TOTP/JWT/CSRF específicos, llaves, recuperación, fuente del corpus, responsables individuales y calendario que U2 no fija están marcados como pendientes o propuestas no aprobadas.
- La primera comprobación del corpus falló con `AssertionError: missing PDF case: EmbeddedFiles`; causa: faltaba esa clave de adjuntos en la lista de variantes. Se agregó `/EmbeddedFiles` y anotaciones de archivo; la comprobación final de variantes requeridas pasó.
- Revisión estructural: 12 documentos tienen propósito e impacto de ausencia; 14 amenazas, 18 rutas y casos PDF activos requeridos se encontraron. `git diff --check` sin errores.
- `gh pr checks 1` y `gh pr checks 2` devolvieron “no checks reported” (salida 1); no hay resultado de CI que pueda afirmarse como aprobado.
- Revisión independiente de seguridad: primer pase halló cuatro ambigüedades de contrato (CSRF de login, descarga, recuperación MFA, fallback HIBP); se corrigieron. Segundo pase: no quedan hallazgos documentales bloqueantes. Esto no revisa código ni prueba implementación.
- PR 1: [`Document trust boundaries and threats`](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/1), 221 líneas cambiadas, base `main`, commit `86f832b`.
- PR 2: [`Add API and operations documentation`](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/2), basado en PR 1, commit principal `0b2a83a` más seguimientos de registro/evidencia visibles en su historial; ambos están abiertos y no se han integrado a `main`.

## Parcial / no verificado

| Objetivo | Estado de Fase 1 | Éxito funcional verificado |
|---|---|---:|
| OBJ-01 | Artefactos de arquitectura/STRIDE redactados; pruebas de controles no ejecutadas y diseño pendiente de decisiones del equipo. | 0% |
| OBJ-02 | Rutas documentadas, no implementadas; OpenAPI generado, autenticación, cobertura, spoofed-IP y purga no probados. | 0% |

El 0% indica ausencia de evidencia de ejecución/cumplimiento funcional; no niega que se redactaron los documentos. No se modificó código y no había aplicación con la que correr pruebas de runtime. Los límites de `docs/limites.md` son recomendaciones para aprobación, no valores medidos ni configuración activa.

## Riesgos y preguntas abiertas

1. Aprobar o ajustar límites de tamaño, píxeles, páginas, tasa, CPU/memoria y tiempo de `docs/limites.md`.
2. Dar fechas reales: inicio, revisiones y demo/entrega; asignar responsable por tarea a Luis Emilio Jaras Sánchez y Antonio de Hoyos Hernández.
3. Confirmar recuperación si se pierden simultáneamente contraseña/TOTP/códigos; el correo solo no desactiva MFA.
4. Confirmar qué conjunto de 20 contraseñas filtradas se usará sin guardar secretos en Git.
5. Definir identidad/contacto del responsable del aviso y el proveedor/región de correo.
6. Definir el canal IPC API–worker y fuente/rotación de llaves antes del backend.

## Cierre de fase

Sin código, corpus generado o pruebas ejecutadas; no declarar OBJ-01/02 cumplidos. La siguiente fase del prompt es diseño, pero `docs/diseno/metaguard-design-spec.json` aún no existe. Esperar confirmación del usuario antes de Fase 2 y acordar cómo crear/aportar esa especificación.
