# Fase 3 (seguimiento) — Backend (OBJ-01/02)

Fecha de inicio: 30 de octubre de 2026. Esta es la Fase 3 del seguimiento ODD; la propuesta U2 denomina a OBJ-01/02 como su primer hito base. Rama apilada: `feat/phase3-backend`, sobre la rama de diseño visual; PR todavía no creado.

## Autorización y decisiones

- El usuario aprobó el plan de backend el 30-10-2026.
- El usuario aprobó para demo todos los límites de `docs/limites.md`: 25 MiB por archivo; imagen hasta 8,000 px por lado y 40 MP; PDF hasta 100 páginas; 60 s por archivo; worker de 1 vCPU/1 GiB/1 trabajo activo; tasa general 60/min/IP y 120/min/cuenta; registro 5/h/IP; carga 3/min/IP y 10/h/cuenta; bloqueo progresivo tras 5 fallos del par cuenta+IP por 1, 5 y 15 min. Ninguno está medido ni aprobado para producción.
- El usuario eligió Docker Secrets montados al runtime como fuente de secretos de demo. KMS, rotación productiva y responsables siguen pendientes; el worker no recibe llaves hasta definir y revisar un canal seguro.
- No se retrofechan commits ni se alteran autores/fechas. Los commits serán cortos, básicos y en inglés según la preferencia del usuario.

## Plan de trabajo

| Unidad | Alcance | Evidencia de cierre |
|---|---|---|
| 1a. Runtime base | FastAPI, configuración fail-closed, lector de secretos, liveness y pruebas | Implementado en `da1bbd1` sobre `feat/phase3-backend`; evidencia abajo. No conecta DB ni monta secretos todavía. |
| 1b. Persistencia | PostgreSQL, SQLAlchemy/Alembic y modelos | Pendiente de definir esquema mínimo de cuenta, reportes y eventos sin ampliar datos personales. |
| 2. Auth y acceso | Registro/login, cookies seguras, CSRF/Origin, Argon2id, TOTP, autorización por objeto y límites | Pruebas de autenticación/CSRF/BOLA/tasa; revisión independiente de seguridad antes de cerrar |
| 3. Ciclo de archivo | Carga acotada sin parsear en API, hash, descarga de un uso, retención/purga | Pruebas de límite, propiedad, replay/expiración/borrado y restos/logs |
| 4. Proxy y ejecución | Nginx con origen de IP confiable; servicios demo, límites de recursos y secreto montado | Validación de configuración y prueba contra `X-Forwarded-For` falsificado |

La limpieza/neutralización, la integración con el worker y su transferencia de datos/llaves pertenecen a la fase siguiente o requieren una decisión de IPC antes de escribir ese camino. El backend no debe afirmar que un archivo subido quedó limpio.

## Progreso y evidencia

### Subunidad 1a — runtime, configuración y liveness

- Creado `backend/` con FastAPI, settings validados y valores de límites aprobados para demo. Los límites aún son solo configuración: todavía no hay endpoint de carga ni middleware de tasa que los aplique.
- Creado `SecretStore`: lee exclusivamente nombres allowlisted desde Docker Secret files. Las lecturas binarias preservan cada byte; la normalización de saltos de línea solo ocurre en `read_text`. No hay valores de secretos en el repo ni un Compose que los monte.
- `/health/live` responde solo `{"status":"ok"}`; no abre DB, lee secretos o revela dependencias. En `production` `/docs` y `/openapi.json` están deshabilitados por defecto.
- `uv` se eligió porque estaba instalado en el entorno (0.11.2) y produce `uv.lock`; Python verificado 3.12.10. `uv sync --all-groups` instaló dependencias para ejecutar pruebas; este uso de red fue solo descarga de paquetes.
- La unidad incluye 384 líneas de cambios de código, pruebas y documentación; `uv.lock` aporta 578 líneas generadas por la herramienta para fijar la resolución. No se redujo documentación ni cobertura para ajustarse al presupuesto.
- Verificación final: `uv run pytest` → **15 passed**, cobertura **100%** del código existente (la regla global pide ≥70%); `uv run ruff check .` → **All checks passed!**; `uv run ruff format --check .` → **7 files already formatted**; `uv lock --check` → **Resolved 30 packages**; `git diff --check` sin errores.
- Prueba de runtime con `uv run uvicorn metaguard_api.main:app --host 127.0.0.1 --port 8765 --no-access-log`: respuesta de `GET /health/live` `{"status":"ok"}` y `GET /docs` devolvió `404` con la configuración predeterminada.
- Revisión de seguridad independiente: primer pase encontró validación positiva faltante en lockout, mutación de bytes binarios por normalización de CR/LF y frase de aprobación de tasas obsoleta. Se corrigieron y re-revisaron sin hallazgos bloqueantes. Esto cubre solo el esqueleto/configuración; no autentica ni cifra datos.
- El entorno actual no expone `/gentle:changes` ni una acción de revisión nativa; no se activó nada. Para esta subunidad se inspeccionó el diff manualmente y se solicitó revisión independiente. Antes de cerrar auth, cifrado o procesamiento, recordar al usuario la revisión nativa y esperar su decisión si sigue sin estar disponible.
- Ajustes derivados de pruebas: el primer `pytest` no resolvió el import del paquete; `pythonpath=["."]` lo corrigió. Starlette marcó el uso de `httpx` como obsoleto en la versión resuelta; se cambió el cliente de prueba a `httpx2` y la suite final pasó sin esa advertencia.

### Estado de la fase

- Completado: subunidad 1a (scaffold/liveness/config/lector de secretos), commit `da1bbd1` (`Add backend health scaffold`).
- Registro de aprobación y decisiones: `ca8160e` (`Approve demo backend limits`).
- Código y decisiones están subidos a `origin/feat/phase3-backend`; aún no hay PR. El diff actual tiene 957 líneas incluyendo 578 generadas en `backend/uv.lock`. El límite de 400 requiere aprobación `size:exception` porque separar el lockfile no produciría una unidad más pequeña/revisable.
- Pendiente: DB/migraciones, auth/CSRF/TOTP, permisos, límites efectivos, carga/descarga/purga, Nginx y Compose.
- OBJ-01/02 funcional: **no cumplidos**; 100% de cobertura del scaffold no es 70% de cobertura de toda la API ni verifica criterios U2.

## Pendientes que no se inventarán

- TTL exacto de JWT/desafío MFA, contrato final de CSRF y parámetros de Argon2id.
- Esquema final de reportes/eventos y campos cifrados; retención y borrado de respaldos.
- Canal API–worker y uso efímero de llave en procesamiento; proveedor/rotación productiva.
- Flujo completo de recuperación (TTL y espera); se pospone para no crear un bypass de MFA.

## Estado inicial

- Backend, OpenAPI ejecutable, migraciones, pruebas y despliegue: **no existen** al comenzar esta fase.
- Las decisiones anteriores quedaron aprobadas; aún no hay controles funcionales verificados.
- OBJ-01/02: 0% de éxito funcional verificado al inicio. Las cifras solo cambiarán con evidencia de ejecución real.
