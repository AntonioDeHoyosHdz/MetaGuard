# Persistencia y mantenimiento

## Qué existe

`backend/metaguard_api/database.py` crea explícitamente un engine PostgreSQL con psycopg y una sesión nueva por transacción. Al salir confirma; ante error revierte; siempre cierra la sesión. `Database.close()` libera el pool. Importar el módulo no lee secretos ni conecta a la base. La sonda `/health/ready` ejecuta `SELECT 1`: reutiliza el pool cuando se inyectó una base de datos o crea y cierra su propio engine. La sonda no demuestra que existan tablas o migraciones.

El password se lee solo del archivo `postgres_password` del directorio de secretos. No existe fallback a password en variables de entorno. `URL.create` evita interpolar credenciales en una URL; `echo=False` y `hide_parameters=True` evitan logs SQL con parámetros. No imprimir objetos internos ni tracebacks de conexión hacia clientes.

## Configuración no secreta

| Variable | Valor inicial |
|---|---|
| `METAGUARD_DB_HOST` | `db` |
| `METAGUARD_DB_PORT` | `5432` |
| `METAGUARD_DB_NAME` | `metaguard` |
| `METAGUARD_DB_USER` | `metaguard` |
| `METAGUARD_DB_SECRET_DIR` | `/run/secrets` |

Estos son valores predeterminados de configuración, no credenciales ni una topología productiva aprobada. El runtime de demo exige una instancia de loopback y la base descartable `metaguard_test`; consulta la [guía local](desarrollo-local.md). Separa el directorio de secretos de PostgreSQL del general de la API y mantén ambos fuera del repositorio.

## Alembic

Desde `backend/`:

```powershell
uv run alembic upgrade head --sql
```

El modo offline genera SQL PostgreSQL sin secretos ni conexión. Además de las revisiones iniciales de caché y cuentas, el esquema incluye verificación de correo, sesiones, TOTP y códigos de recuperación, reportes y permisos de descarga, eventos de sistema y cuota de VirusTotal. El SQL generado no sustituye verificar la versión efectiva en PostgreSQL con `alembic current`.

El comando online `uv run alembic upgrade head` necesita PostgreSQL accesible y el archivo de secreto montado. Lee configuración al ejecutar, no guarda una URL con password en `alembic.ini` y cierra su engine incluso si falla. No ejecutar contra una DB de producción; no se ha definido TLS, respaldo ni rol de migraciones productivo.

## Evidencia y límites

Las pruebas con SQLite y el test de URL sin conexión comprueban transacciones y tratamiento de credenciales sin demostrar conectividad con PostgreSQL. La [verificación local](#verificación-local-con-postgresql-real) cubre también un servidor PostgreSQL descartable. Esto no acredita un despliegue ni cifrado integral de la base de datos; los reportes omiten los valores extraídos en vez de persistirlos cifrados por campo.

## Caché de reputación

La caché guarda un SHA-256 de 32 bytes, un veredicto (`malicious`, `suspicious`, `undetected` o `no_record`) y su vencimiento en segundos UTC. Puede guardar estadísticas minimizadas y fecha de análisis cuando están disponibles. No almacena nombres, archivos, usuarios ni respuestas completas del proveedor. `undetected` no significa que el archivo sea seguro; `no_record` indica ausencia de registro.

El acceso omite entradas vencidas desde las 24 horas; la eliminación se realiza mediante la purga transaccional. El [cliente opcional de VirusTotal](api.md#consulta-de-reputación) usa la caché solo tras consentimiento y aplica una cuota global persistida, con tiempo del servidor. El proveedor está desactivado en la demo. No ejecutes mantenimiento sobre una base existente sin autorización.

El comando independiente `python -m metaguard_api.maintenance schedule-reputation` conserva su ciclo de caché, reportes y eventos al iniciar y luego cada 60 segundos; `--interval-seconds` permite ajustar el intervalo entre 1 y 3600 segundos. Ante un fallo escribe un error genérico y vuelve a intentar en el siguiente intervalo; `SIGTERM` solicita una salida ordenada. No se modificó ni se activa desde la API. Por separado, una API con dependencias de archivos inyectadas ejecuta el ciclo `purge-maintenance` durante su propio ciclo de vida, al iniciar y cada 60 segundos, y además purga las entradas vencidas de su store cifrado local al proceso. Sus sentencias PostgreSQL tienen un límite de 5 segundos; al apagar la API, la cancelación espera a que la operación bloqueante en curso termine antes de cerrar el ciclo. Ninguna de estas opciones configura systemd, Docker ni la supervisión del host; si la API o el servicio independiente deja de ejecutarse, o la DB/red falla, pueden permanecer datos vencidos. No se garantiza la retención física hasta verificar funcionamiento y alertas en el entorno real.

Las migraciones incluyen downgrade para entornos de prueba; revertir una tabla poblada elimina su contenido y requiere una decisión explícita.

El comando existente `purge-reputation` conserva su alcance y salida: borra solo caché vencida y no requiere el esquema de eventos. `purge-maintenance` purga en una misma transacción la caché, los reportes vencidos y los eventos de seguridad con 30 días o más; informa conteos y revierte los borrados conjuntos si falla alguno. El ciclo periódico del CLI ejecuta esa operación con `schedule-maintenance` o el alias compatible `schedule-reputation`. La API configurada también invoca la misma operación en su ciclo de vida; varios workers pueden repetir el borrado de filas expiradas sin un lock distribuido, mientras cada uno purga únicamente su propio store en memoria. El CLI no puede borrar stores de otros procesos y los archivos temporales no se vuelven portables entre workers. La supervisión del host y la garantía de retención durante caídas quedan fuera de ambos mecanismos.

## Verificación local con PostgreSQL real

En un contenedor PostgreSQL 16.13 efímero, con puerto ligado solo a loopback y un volumen anónimo propio del contenedor, pasaron `alembic upgrade head`, `alembic check`, `downgrade base`, `upgrade head` y una segunda comprobación de Alembic. También se ejercitaron inserción de cuenta, hash Argon2, preparación/confirmación TOTP, rechazo de reutilización y una carrera entre dos sesiones sobre el mismo paso; solo una aceptó. `purge-maintenance` eliminó un evento de más de 30 días y preservó uno dentro de retención. El contenedor y su volumen de prueba se eliminaron.

En ensayos locales posteriores se aplicaron las migraciones hasta `0011_mfa_recovery_codes`, pasaron seis pruebas optativas de integración y se [restauró un respaldo sintético en PostgreSQL 17.6](validacion-staging.md#evidencia-local-restauración-de-respaldo). Faltan el entorno separado de staging, TLS y la operación de respaldos y supervisión de producción.

La suite optativa incluye registro, verificación y una carrera de TOTP contra PostgreSQL real. Antes de ejecutarla, configura y migra la [base descartable de loopback](desarrollo-local.md#1-preparar-postgresql-y-las-llaves). Desde `backend/`:

```powershell
$env:METAGUARD_RUN_POSTGRES_TESTS = "1"
uv run --offline --no-sync pytest --no-cov tests/test_postgresql_integration.py -q
```

La prueba rechaza cualquier host no local o nombre de base distinto de `metaguard_test`. Usa solo una base descartable, nunca datos de producción. Si falta la variable explícita, se omite en la suite habitual.

## Alternativa propuesta: Supabase para pruebas

**Estado: pendiente; no existe una integración de pruebas remotas ni se ha conectado un proyecto Supabase.** La protección local anterior permanece sin cambios. La suite inserta y elimina datos, y las migraciones modifican el esquema: no deben ejecutarse en una base de producción ni en un proyecto compartido.

Para habilitar una prueba remota se necesita, primero, un proyecto Supabase dedicado y descartable, identificado y autorizado explícitamente. La ejecución remota requerirá un mecanismo de prueba independiente con protección verificable del destino, TLS con verificación del servidor y manejo de credenciales fuera del repositorio. Hasta disponer de ese mecanismo, no se debe cambiar el host ni desactivar el guard de las pruebas locales para intentar la conexión. No se deben copiar contraseñas, URL de conexión ni certificados privados al repositorio o a la conversación.

Supabase documenta que la conexión directa gratuita utiliza IPv6, mientras que el pooler compartido en modo sesión admite IPv4; el modo transacción tiene restricciones de sesión. Para verificar TLS con `verify-full`, consulte la documentación del proveedor y su certificado de CA. La selección y la compatibilidad del endpoint concreto siguen pendientes de verificación. Referencias: [conexiones PostgreSQL](https://supabase.com/docs/guides/database/connecting-to-postgres) y [TLS para PostgreSQL](https://supabase.com/docs/guides/platform/ssl-enforcement).

## Comprobación parcial con PGlite

En una prueba temporal y en memoria, `@electric-sql/pglite` 0.5.16 ejecutó el SQL PostgreSQL generado offline por Alembic hasta la revisión `0006_email_verification`. Se observaron siete tablas, el rechazo de correos con mayúsculas o duplicados y la reversión de una transacción explícita con datos sintéticos. Una revisión independiente volvió a ejecutar las comprobaciones y confirmó sus resultados.

Esta prueba no ejecutó el backend ni sus pruebas de integración PostgreSQL, Alembic online, el driver psycopg, conexiones concurrentes o pruebas de carrera. PGlite tiene una conexión interna y no sustituye una comprobación con un servidor PostgreSQL real. La instalación y la base fueron temporales; no se incorporó PGlite como dependencia del proyecto.
