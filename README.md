# MetaGuard

Plataforma web para detectar, explicar y eliminar metadatos de imágenes JPG/PNG y PDF. Consulta la propuesta y el estado real del avance en `docs/`.

## Estado

- La interfaz es una demostración visual desconectada; no envía ni procesa archivos.
- La API expone comprobaciones de vida y disponibilidad; dispone de componentes internos de caché y contraseñas, pero no de registro ni inicio de sesión.
- Existen migraciones para la caché y la estructura inicial de cuentas. Se probaron con SQLite y SQL PostgreSQL generado sin conexión, no en PostgreSQL real.
- El proceso de purga está implementado, pero no está desplegado ni supervisado. Procesamiento aislado, integración con frontend y despliegue siguen pendientes.
- El detalle y las limitaciones están en `docs/backend-persistencia.md` y `odd/tasks/metaguard-completion.md`.

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

## Vista visual del frontend

Esta es una **demostración desconectada**: no acepta archivos ni ejecuta análisis o limpieza. Requiere Node.js y npm; desde `frontend/`:

```powershell
npm ci
npm run dev
```

Abre la dirección local que indique Vite. Para comprobar la vista, ejecuta `npm test`. La animación utiliza una secuencia local de 20 fotogramas con respaldo SVG; aún faltan mediciones de rendimiento y auditoría completa de accesibilidad.
