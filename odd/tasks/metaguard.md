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
- [x] Publicar PR 2 apilado sobre PR 1 y verificar las referencias remotas; no hacer merge.

Forecast: ~500 authored changed lines al incluir el reporte y el seguimiento; la revisión inicial cuenta 431 líneas antes de añadir el reporte. Estrategia seleccionada por el usuario: `stacked-to-main`.

| Slice | Alcance | Dependencia | Presupuesto planeado |
|---|---|---|---:|
| PR 1 — foundation | Arquitectura, flujo, STRIDE, datos, riesgo de metadatos y correcciones del inventario | `main` | 221 líneas, commit `86f832b`, [PR 1](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/1) |
| PR 2 — API/operations | Límites, API, llaves, recuperación, corpus, aviso, plan y reporte Fase 1 | PR 1 | Rama `docs/phase1-02-api-ops`; commit principal `0b2a83a`; seguimientos registrados en el historial del [PR 2](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/2) |

## Evidencia previa
- `docs/propuesta-u2.txt`: extracción local de la propuesta U2, 19 páginas.
- `docs/trazabilidad.md`: estado y criterios OBJ-01…OBJ-07.
- `docs/avance/fase-0.md`: inventario; `odd/tasks/metaguard.md`: estado remoto GitHub.
- Repositorio privado: `https://github.com/AntonioDeHoyosHdz/MetaGuard`.
- El usuario eligió `stacked-to-main` el 30-10-2026; PR 1 y PR 2 se mantendrán como unidades separadas, con PR 2 basado en PR 1.
- PR 1: commit `86f832b`, [Document trust boundaries and threats](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/1); estado abierto, base `main`.
- PR 2: commit principal `0b2a83a` (docs); los seguimientos de cadena/evidencia están en el historial de [Add API and operations documentation](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/2); estado abierto, base `docs/phase1-01-foundation`. No se hizo merge.
- Revisión independiente inicial encontró cuatro huecos de contrato (CSRF de login, autorización de descarga, recuperación MFA y fallback HIBP); se corrigieron y el revisor confirmó que no quedan hallazgos bloqueantes documentales.
- `docs/avance/fase-1.md` registra el resultado; propuesta y reporte no cuentan como prueba de implementación.

## Estado
- Fase 0: completada, 0% de objetivos de implementación verificados.
- Fase 1: 12/12 artefactos documentados y revisión de seguridad completada; PR 1 y PR 2 abiertos en cadena.
- Fase 2 quedó pendiente de diseño y confirmación del usuario.

## Alcance actual — Fase 2: diseño visual (OBJ-04)

El usuario solicitó preparar una dirección original basada en las capturas de referencia: experiencia cinematográfica, objetos 3D y transiciones fluidas, adaptados a privacidad de archivos. Las capturas inspiran cualidades generales; no se copiarán composición, texto, marca, persona ni activos criptográficos.

- [x] Crear `docs/diseno/metaguard-design-spec.json` con tokens, movimiento, escena 3D y contraste.
- [x] Documentar decisiones visuales, pantallas/estados y concepto/presupuesto 3D.
- [x] Verificar pares de contraste con herramienta y registrar resultados reales.
- [x] Revisar accesibilidad, movimiento reducido, rendimiento y reglas de recursos locales.
- [x] Crear reporte Fase 2; no iniciar código antes de la aprobación del diseño.
- [x] Publicar avances de diseño en `docs/phase2-visual-design`; ver referencias de commits reales.
- [x] Abrir PR 3 apilado sobre PR 2 y verificar referencias remotas; no hacer merge.

Forecast: ~300 authored changed lines; mantener una unidad/PR bajo 400. La estrategia `stacked-to-main` continúa: la rama/PR de Fase 2 dependerá de PR 2 mientras este siga abierto.

## Preferencias de entrega registradas

- Mensajes de commit cortos y comprensibles en inglés básico; publicar los avances por unidades pequeñas.
- No falsificar fechas, autores ni actividad histórica. Los nuevos commits usarán su fecha real y no se reescribirá el historial existente.
- Commits Fase 2 ya publicados en secuencia real: `793252c` (plan), `1f2f7b4` (tokens), `c2e607f` (decisiones), `353d8fb` (interfaz), `5eec9d1` (escena 3D), `a2c0bc1` (recursos locales/CSP). El reporte de fase registra la auditoría.
- Fase 2: 4/4 artefactos documentados y paleta auditada; rendimiento 3D/UI real pendientes; PR 3 abierto, aprobación del diseño pendiente antes de Fase 3.
- PR 3: [Add MetaGuard visual design](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/3), abierto sobre `docs/phase1-02-api-ops`; no se hizo merge.
