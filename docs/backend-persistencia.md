# Base de persistencia — parcial

## Qué existe

`backend/metaguard_api/database.py` crea explícitamente un engine PostgreSQL con psycopg y una sesión nueva por transacción. Al salir confirma; ante error revierte; siempre cierra la sesión. `Database.close()` libera el pool. Importar el módulo no lee secretos ni conecta a la base. La sonda `/health/ready` invoca el helper bajo demanda, consulta `SELECT 1` y cierra el engine; su tiempo de conexión configurado es de tres segundos. La sonda no demuestra que existan tablas o migraciones.

El password se lee solo del archivo `postgres_password` del directorio de secretos. No existe fallback a password en variables de entorno. `URL.create` evita interpolar credenciales en una URL; `echo=False` y `hide_parameters=True` evitan logs SQL con parámetros. No imprimir objetos internos ni tracebacks de conexión hacia clientes.

## Configuración no secreta

| Variable | Valor inicial |
|---|---|
| `METAGUARD_DB_HOST` | `db` |
| `METAGUARD_DB_PORT` | `5432` |
| `METAGUARD_DB_NAME` | `metaguard` |
| `METAGUARD_DB_USER` | `metaguard` |
| `METAGUARD_DB_SECRET_DIR` | `/run/secrets` |

Estos son nombres técnicos de servicio/base/rol para el futuro despliegue local, no una credencial ni una topología productiva aprobada. El directorio de secretos de DB se configura por separado del directorio general de la API. No crear secretos reales dentro del repositorio; falta el Compose que monte el archivo.

## Alembic

Desde `backend/`:

```powershell
uv run alembic upgrade head --sql
```

El modo offline genera SQL PostgreSQL sin secretos ni conexión. La revisión `0001_reputation_cache` define la caché de reputación; `0002_accounts` añade la estructura inicial de cuentas. No existen tablas de reportes ni eventos. El SQL generado no demuestra que la migración funcione en un servidor PostgreSQL real.

El comando online `uv run alembic upgrade head` necesita PostgreSQL accesible y el archivo de secreto montado. Lee configuración al ejecutar, no guarda una URL con password en `alembic.ini` y cierra su engine incluso si falla. No ejecutar contra una DB de producción; no se ha definido TLS, respaldo ni rol de migraciones productivo.

## Evidencia y límites

Las pruebas usan SQLite exclusivamente para ciclo de transacciones y harness de Alembic. El test de URL captura la construcción del engine sin conexión y verifica password con caracteres reservados, repr oculto y parámetros no logueados. Esto **no demuestra compatibilidad ni conectividad PostgreSQL**.

Docker responde en el entorno actual, pero la conexión a PostgreSQL real todavía no se ha probado. La estructura inicial de cuentas existe, pero no hay tablas de reportes o eventos, cifrado de campos, autenticación ni despliegue.

## Caché de reputación

La caché guarda únicamente un SHA-256 de 32 bytes, un resultado limitado (`malicious`, `suspicious`, `undetected` o `no_record`) y su vencimiento en segundos UTC. No almacena nombres, archivos, usuarios ni respuestas completas del proveedor. `undetected` no significa que el archivo sea seguro; `no_record` indica ausencia de registro.

El acceso omite entradas desde las 24 horas y existe una operación transaccional para purgarlas. El comando `python -m metaguard_api.maintenance purge-reputation` ejecuta una purga puntual con la configuración y secretos de la base; devuelve error sin detalles sensibles si falla. No lo ejecutes sobre una base existente sin autorización. **La purga programada aún no está conectada**: una entrada vencida puede seguir almacenada hasta ejecutar esa operación. La consulta externa, el consentimiento, el cliente y el mapeo real de resultados también están pendientes. El tiempo debe provenir del servidor, no del usuario.

El proceso `python -m metaguard_api.maintenance schedule-reputation` ejecuta la purga conjunta de caché y eventos al iniciar y después cada 60 segundos; `--interval-seconds` permite ajustar el intervalo entre 1 y 3600 segundos. Ante un fallo escribe un error genérico y vuelve a intentar en el siguiente intervalo; `SIGTERM` solicita una salida ordenada. Debe ejecutarse como servicio separado con reloj correcto, supervisión y acceso a los secretos necesarios. **Todavía no está instalado ni activado en un despliegue**, y una caída o retraso puede mantener registros vencidos más de 24 horas; no se garantiza la retención física hasta verificar funcionamiento y alertas en el entorno real.

La migración incluye downgrade para entornos de prueba; revertir una tabla poblada elimina su contenido y requiere una decisión explícita. No se ha aplicado a una base real en esta unidad.

El comando existente `purge-reputation` conserva su alcance y salida: borra solo caché vencida y no requiere el esquema de eventos. `purge-maintenance` purga en una misma transacción la caché y los eventos de seguridad con 30 días o más; informa ambos conteos y revierte ambos borrados si falla alguno. El ciclo programado ejecuta la misma operación conjunta; se inicia con `python -m metaguard_api.maintenance schedule-maintenance` o el nombre compatible `schedule-reputation`. No está supervisado ni instalado todavía; la retención física continúa sin garantía durante caídas.

## Verificación local con PostgreSQL real

En un contenedor PostgreSQL 16.13 efímero, con puerto ligado solo a loopback y un volumen anónimo propio del contenedor, pasaron `alembic upgrade head`, `alembic check`, `downgrade base`, `upgrade head` y una segunda comprobación de Alembic. También se ejercitaron inserción de cuenta, hash Argon2, staging/confirmación TOTP, replay y una carrera entre dos sesiones sobre el mismo paso; solo una aceptó. `purge-maintenance` eliminó un evento de más de 30 días y preservó uno dentro de retención. El contenedor y su volumen de prueba se eliminaron. Esto demuestra la compatibilidad local con ese motor; no prueba recuperación de respaldos, TLS, producción ni supervisión de servicios.

La regresión de TOTP también tiene una prueba optativa contra PostgreSQL real. Desde `backend`, configurá `METAGUARD_DB_HOST` a `127.0.0.1`, `localhost` o `::1`, `METAGUARD_DB_NAME` exactamente como `metaguard_test` y `METAGUARD_DB_SECRET_DIR` con el secreto de prueba; luego ejecutá:

```powershell
$env:METAGUARD_RUN_POSTGRES_TESTS = "1"
python -m pytest tests/test_postgresql_integration.py -q
```

La prueba rechaza cualquier host no local o nombre de base distinto. Usá solo una base descartable, nunca datos de producción. Sin la variable explícita, el test queda omitido en la suite habitual.
