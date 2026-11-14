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

El modo offline genera SQL PostgreSQL sin secretos ni conexión. Actualmente solo produce una transacción vacía: **no hay revisiones ni tablas de negocio**. El template de revisión está preparado, pero no se generará una migración hasta resolver el esquema.

El comando online `uv run alembic upgrade head` necesita PostgreSQL accesible y el archivo de secreto montado. Lee configuración al ejecutar, no guarda una URL con password en `alembic.ini` y cierra su engine incluso si falla. No ejecutar contra una DB de producción; no se ha definido TLS, respaldo ni rol de migraciones productivo.

## Evidencia y límites

Las pruebas usan SQLite exclusivamente para ciclo de transacciones y harness de Alembic. El test de URL captura la construcción del engine sin conexión y verifica password con caracteres reservados, repr oculto y parámetros no logueados. Esto **no demuestra compatibilidad ni conectividad PostgreSQL**.

Docker responde en el entorno actual, pero la conexión a PostgreSQL real todavía no se ha probado. Tampoco hay esquema de usuarios/reportes/eventos, cifrado de campos, auth, purga ni despliegue.

Rollback de esta unidad: retirar el helper, `alembic.ini`, `migrations/`, sus dos archivos de prueba y referencias documentales. No hay migraciones aplicadas ni datos que revertir.
