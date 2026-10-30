# ODD — MetaGuard

## Objetivo
Desarrollar MetaGuard conforme a la propuesta U2 y al prompt operativo, documentando decisiones con evidencia y sin iniciar fases no autorizadas.

## Alcance actual — Fase 1: documentación base (OBJ-01 y OBJ-02)
Plan aprobado por el usuario el 30 de octubre de 2026. Sin código ni afirmaciones de implementación.

- [x] Documentar arquitectura, límites de confianza, flujo de carga/retención, entidades y clasificación de riesgo.
- [x] Crear matriz STRIDE con 14 amenazas, controles y pruebas aún pendientes de ejecución.
- [ ] Proponer límites numéricos, claramente no aprobados, y documentar ≥12 endpoints.
- [ ] Documentar llaves/secretos, recuperación y corpus sin inventar datos reales.
- [ ] Crear aviso de privacidad y plan con riesgos, responsables/fechas pendientes del usuario.
- [ ] Revisar coherencia/seguridad, crear reporte de fase y cerrar Fase 1.

Forecast: ~500 authored changed lines al incluir el reporte y el seguimiento; la revisión inicial cuenta 431 líneas antes de añadir el reporte. Estrategia seleccionada por el usuario: `stacked-to-main`.

| Slice | Alcance | Dependencia | Presupuesto planeado |
|---|---|---|---:|
| PR 1 — foundation | Arquitectura, flujo, STRIDE, datos, riesgo de metadatos y correcciones del inventario | `main` | ~240 líneas |
| PR 2 — API/operations | Límites, API, llaves, recuperación, corpus, aviso, plan y reporte Fase 1 | PR 1 | ~300 líneas |

## Evidencia previa
- `docs/propuesta-u2.txt`: extracción local de la propuesta U2, 19 páginas.
- `docs/trazabilidad.md`: estado y criterios OBJ-01…OBJ-07.
- `docs/avance/fase-0.md`: inventario; `odd/tasks/metaguard.md`: estado remoto GitHub.
- Repositorio privado: `https://github.com/AntonioDeHoyosHdz/MetaGuard`.
- El usuario eligió `stacked-to-main` el 30-10-2026; PR 1 y PR 2 se mantendrán como unidades separadas, con PR 2 basado en PR 1.
- Revisión independiente inicial encontró cuatro huecos de contrato (CSRF de login, autorización de descarga, recuperación MFA y fallback HIBP); se corrigieron y el revisor confirmó que no quedan hallazgos bloqueantes documentales.

## Estado
- Fase 0: completada, 0% de objetivos de implementación verificados.
- Fase 1: plan aprobado; slice 1 documentado y revisado; slice 2/report pendiente.
- Siguiente paso tras el cierre: mostrar reporte y esperar confirmación antes de Fase 2.
