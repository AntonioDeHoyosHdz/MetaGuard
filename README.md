# MetaGuard

Plataforma web para detectar, explicar y eliminar metadatos de imágenes JPG/PNG y PDF. Consulta la propuesta y el estado real del avance en `docs/`.

## Estado

- Documentación base y dirección visual: redactadas; PR 1, 2 y 3 siguen apilados y abiertos.
- Backend: esqueleto inicial de FastAPI, valores de límites aprobados para demo (todavía no aplicados a operaciones), lector de secretos montados como archivos (aún sin servicio Docker que los monte) y endpoint de liveness.
- Autenticación, base de datos/migraciones, carga/descarga, purga, procesador y frontend: pendientes; no se declara ningún objetivo funcional completado.
- Los límites aprobados son valores iniciales de demo, no mediciones ni valores de producción.
- SQLAlchemy, Alembic y psycopg están fijados en el lockfile para la siguiente unidad de persistencia; instalarlos no crea tablas ni activa la conexión en la API.
- Hay un helper de conexión/transacciones y harness Alembic vacío; ver `docs/backend-persistencia.md`. PostgreSQL real y modelos de negocio siguen sin verificar/implementar.

## Probar el backend inicial

Requiere Python 3.12 y `uv`. Desde `backend/`:

```powershell
uv sync --all-groups
uv run pytest
$env:METAGUARD_ENVIRONMENT = "development"
uv run uvicorn metaguard_api.main:app --reload --port 8000
```

El chequeo `GET /health/live` responde solo `{"status":"ok"}` y no requiere base de datos ni secretos. La configuración predeterminada oculta `/docs` y `/openapi.json`; la variable de desarrollo anterior habilita `/docs` localmente. Esta etapa aún no configura un despliegue Docker.

## Seguridad

No guardes secretos, contraseñas, archivos de usuarios ni datos reales del corpus en Git. Para la demo, el diseño aprobado usa Docker Secrets montados al runtime; crea esos valores fuera del repositorio cuando se incorpore el Compose. KMS y la rotación de producción continúan pendientes.
