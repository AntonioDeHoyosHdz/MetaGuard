# ODD — MetaGuard

## Objetivo
Desarrollar MetaGuard conforme a la propuesta U2 y al prompt operativo, documentando decisiones con evidencia y sin iniciar fases no autorizadas.

## Alcance actual — Fase 1: documentación base (OBJ-01 y OBJ-02)
Plan aprobado por el usuario el 30 de octubre de 2026. Sin código ni afirmaciones de implementación.

- [x] Documentar arquitectura, límites de confianza, flujo de carga/retención, entidades y clasificación de riesgo.
- [x] Crear matriz STRIDE con 14 amenazas, controles y pruebas aún pendientes de ejecución.
- [x] Proponer límites numéricos, claramente no aprobados, y documentar 18 rutas API.
- [x] Documentar llaves/secretos, recuperación y corpus sin incluir datos reales.
- [x] Crear aviso de privacidad y plan con riesgos, responsables/fechas pendientes del usuario.
- [x] Revisar coherencia/seguridad y crear reporte de fase; no declarar objetivos funcionales cumplidos.
- [ ] Publicar PR 2 apilado sobre PR 1 y verificar las referencias remotas; no hacer merge.

Forecast: ~500 authored changed lines al incluir el reporte y el seguimiento; la revisión inicial cuenta 431 líneas antes de añadir el reporte. Estrategia seleccionada por el usuario: `stacked-to-main`.

| Slice | Alcance | Dependencia | Presupuesto planeado |
|---|---|---|---:|
| PR 1 — foundation | Arquitectura, flujo, STRIDE, datos, riesgo de metadatos y correcciones del inventario | `main` | 221 líneas, commit `86f832b`, [PR 1](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/1) |
| PR 2 — API/operations | Límites, API, llaves, recuperación, corpus, aviso, plan y reporte Fase 1 | PR 1 | Estimado ~300 líneas; rama `docs/phase1-02-api-ops` |

## Evidencia previa
- `docs/propuesta-u2.txt`: extracción local de la propuesta U2, 19 páginas.
- `docs/trazabilidad.md`: estado y criterios OBJ-01…OBJ-07.
- `docs/avance/fase-0.md`: inventario; `odd/tasks/metaguard.md`: estado remoto GitHub.
- Repositorio privado: `https://github.com/AntonioDeHoyosHdz/MetaGuard`.
- El usuario eligió `stacked-to-main` el 30-10-2026; PR 1 y PR 2 se mantendrán como unidades separadas, con PR 2 basado en PR 1.
- Revisión independiente inicial encontró cuatro huecos de contrato (CSRF de login, autorización de descarga, recuperación MFA y fallback HIBP); se corrigieron y el revisor confirmó que no quedan hallazgos bloqueantes documentales.
- `docs/avance/fase-1.md` registra el resultado; propuesta y reporte no cuentan como prueba de implementación.

## Estado
- Fase 0: completada, 0% de objetivos de implementación verificados.
- Fase 1: 12/12 artefactos documentados y revisión de seguridad completada; PR 1 abierto, PR 2 en preparación.
- Siguiente paso tras el cierre: mostrar reporte y esperar confirmación antes de Fase 2.
