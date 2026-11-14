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
- Fase 2: documentación visual terminada y dirección aprobada; PR 3 abierto y sin merge. La implementación visual aún no existe.

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
- Fase 2: 4/4 artefactos documentados y paleta auditada; usuario aprobó la dirección visual el 30-10-2026; rendimiento 3D/UI real pendientes. El usuario aprobó el plan de backend y las decisiones iniciales para demo el 30-10-2026.
- PR 3: [Add MetaGuard visual design](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/3), abierto sobre `docs/phase1-02-api-ops`; no se hizo merge.

## Siguiente fase — Fase 3: backend (OBJ-01/02)

El usuario aprobó el plan de Fase 3, todos los límites propuestos para demo y Docker Secrets montados al runtime el 30-10-2026. La rama `feat/phase3-backend` se apila sobre Fase 2 conforme a `stacked-to-main`.

- Límites iniciales de demo aprobados; su efectividad no está medida: `docs/limites.md`.
- Fuente de secretos para demo: Docker Secrets; KMS y rotación periódica productiva pendientes: `docs/llaves-y-secretos.md`.
- Alcance de seguimiento Fase 3 (U2 Hito 1, OBJ-01/02): runtime/API, modelos/migraciones, autenticación y autorización, flujo acotado de carga/descarga y purga; no incluye limpieza/neutralización de archivos.
- Antes de las partes afectadas deben resolverse/revisarse: JWT/CSRF/TOTP y parámetros de Argon2id; canal API–worker y entrega de llave; recuperación de cuenta. No inventar un bypass de MFA.
- Subunidad 1a implementada: esqueleto FastAPI, límites en settings, lector Docker Secret files, `/health/live`, README y contrato API actualizado. Evidencia de tests y revisión en `docs/avance/fase-3.md`; DB/auth/carga/Compose siguen pendientes.
- `uv` (0.11.2 disponible) se usa con `backend/uv.lock` para dependencias reproducibles; versiones de Python verificada: 3.12.10.
- `/gentle:changes` y revisión nativa no se exponen en este entorno; se hizo inspección manual y revisión independiente. Antes de cerrar auth/cifrado/procesamiento, recordar la revisión nativa y esperar decisión del usuario si no está disponible.
- Commits publicados en `feat/phase3-backend`: `ca8160e` (aprobación de límites demo/secretos), `da1bbd1` (FastAPI/liveness/config/tests) y `be2add2` (registro). No se creó PR: el diff de la rama vs. Fase 2 tiene 1,056 líneas, incluidas 578 líneas generadas de `uv.lock`; pedir autorización `size:exception` antes de abrirlo según la skill de PR encadenados.
- Commits cortos en inglés básico con fechas/autores reales; no reescribir ni retrofechar historial.

## Continuación — persistencia base

- Usuario aprobó `size:exception` y continuar. PR 4 abierto sobre PR 3: https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/4; no merge, sin checks CI reportados. Esta actualización supersede la espera de aprobación anterior.
- Próxima unidad: conexión SQLAlchemy PostgreSQL con password desde Docker Secret, sesiones por operación y entorno Alembic sin entidades de negocio inventadas. Rama hija de PR 4.
- Docker CLI existe pero el daemon Linux no está disponible (pipe dockerDesktopLinuxEngine ausente); integración PostgreSQL real queda NO VERIFICADA mientras no haya daemon. No iniciar servicios del equipo sin necesidad.
- División de persistencia en una pasada: primero dependencias reproducibles (295 líneas generadas + 3 de pyproject y documentación), luego conexión/transacciones/Alembic con pruebas. Mantener cada nuevo PR por debajo de 400, sin extender la excepción de PR 4.
- PR 5 abierto: https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/5; commit `4ea2fe8`, 300 líneas. Rama hija actual `feat/phase3-database-runtime` contiene helper de conexión/transacciones y Alembic sin modelos ni revisiones de negocio. 22 tests pasaron, 100% de cobertura del paquete actual; Ruff/format/lock válidos y SQL offline vacío generado. Revisión independiente sin bloqueantes. PostgreSQL real NO VERIFICADO por daemon Docker no disponible; auth/CSRF/TOTP/IPC y esquema siguen pendientes.
- PR 6 abierto sobre PR 5: https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/6, commit `35021cf`, boundary inicial 259 líneas. PR 5 y 6 sin checks CI reportados, abiertos y sin merge. Siguiente sesión: comprobar PostgreSQL 16 cuando Docker Desktop esté disponible; luego resolver esquema mínimo/TTL JWT-MFA/CSRF/Argon2id antes de auth. No activar revisión nativa sin decisión del usuario. Engram no expuesto; este documento conserva el estado.

## Prioridad aprobada — frontend visual (Fase 5, adelantada)

El usuario aprobó adelantar una interfaz visual sin integrar backend el 30-10-2026. Rama `feat/frontend-visual` apilada sobre `feat/phase3-database-runtime`; los PR anteriores permanecen abiertos, sin merge.

- React 18, TypeScript, Vite, Tailwind y three.js empaquetados localmente; estilo original «El sandbox de vidrio» y transiciones fluidas.
- Mostrar explícitamente la demo y datos sintéticos. No leer/subir archivos reales ni afirmar limpieza, seguridad o progreso de procesamiento no verificable.
- Crear interfaz adaptable, navegación accesible por teclado, `prefers-reduced-motion`, cubo 3D mínimo y respaldo SVG; no agregar partículas sin medir primero el rendimiento.
- Verificar build, pruebas y vista local; registrar resultados reales y límites en el reporte. No publicar recursos externos ni habilitar CDN.
- Backend y motor siguen pendientes; volver a ellos tras el diseño. Commits cortos en inglés, fechas reales; no reescribir historial.
- Avance visual: React 18/TS/Vite/Tailwind y cubo three.js local; flujo de ejemplo sin archivos reales. Pruebas: 5 pasaron, build pasó con advertencia de chunk escena 542.52 kB, `npm audit` 0 vulnerabilidades. Revisión visual desktop/móvil y demo; FPS de 60 s, CSP/tráfico y auditoría de accesibilidad exhaustiva pendientes. Detalle: `docs/avance/fase-5.md`.
- Publicados en `feat/frontend-visual`: `1cabeb0`, `ab5aba1` y `6663a7a`. Sin PR de frontend por ahora: diff del boundary `6663a7a` vs PR 6 = 3,687 líneas (3,009 generadas en lockfile); solicitar `size:exception` para PR apilado. Mantener sin alterar cambios ajenos no relacionados que aparecieron en `docs/` durante el trabajo.

## Continuación — comprobación de contraseñas comprometidas

- [x] Implementar la consulta por prefijo SHA-1 y comparación local de sufijos como componente aislado de OBJ-05, con respuestas simuladas y sin enviar contraseñas; propagar fallos en lugar de considerarlos seguros. Ruta: inline; riesgo: seguridad.
- [x] Verificar el componente y la suite existente sin hacer builds; verificación independiente de 15 casos sin bloqueantes. Suite actual: 29 pruebas aprobadas; Ruff y formato correctos.
- Contexto: dependencias fijadas restauradas desde PyPI con autorización; suite existente: 22 pruebas aprobadas. El flujo de registro, el cliente HTTP real, el mecanismo alternativo local y los eventos siguen pendientes; no se considera completo OBJ-05.
- Solicitud del usuario: «quiero que empieces a generar literalmente todo, todo el front, backend, todo eso»; «Never build after changes.»
- El contrato de prefijo y padding se basa en la [documentación de Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords). El verificador es una biblioteca aislada, no una integración HTTP ni una política de contraseñas completa.

## Continuación — disponibilidad de PostgreSQL

- [x] Conectar una sonda mínima de disponibilidad de base de datos a la API sin cambiar `/health/live`, sin revelar secretos y cerrando la conexión. Ruta: inline; riesgo: contrato compartido y seguridad.
- [x] Cubrir disponibilidad y fallo mediante pruebas HTTP, ejecutar la suite y una verificación independiente: 34 pruebas pasaron; Ruff y formato correctos. La prueba con PostgreSQL real y el esquema de negocio siguen pendientes; no se hizo build.
- La sonda nueva devuelve únicamente disponibilidad, usa un timeout de conexión de tres segundos y no demuestra que exista el esquema. Revisión independiente sin bloqueantes, con driver simulado y sesión SQLite real; no equivale a probar PostgreSQL ni el tiempo transcurrido de conexión.
