# MetaGuard

Aplicación web para revisar y eliminar metadatos de imágenes JPG/PNG y PDF. El procesamiento de archivos se ejecuta en un servicio aislado, no dentro de la API.

## Estado

- **Vista visual:** arranca sin credenciales para recorrer la interfaz. Las sondas de la API se consultan por separado; esta vista no habilita cuentas ni procesamiento.
- **Demo local:** usa PostgreSQL descartable, HTTPS local y secretos de prueba. Sigue la [guía de desarrollo local](docs/desarrollo-local.md) y el [guion de entrega académica](docs/entrega-academica.md).
- **Archivos y reportes:** requieren el [servicio de procesamiento aislado](docs/procesamiento-archivos.md) y su configuración en la API. No hay alternativa que procese archivos cargados dentro de la API. VirusTotal es opcional y requiere consentimiento por archivo.
- **Producción:** no desplegada. La [guía de validación en staging](docs/validacion-staging.md) indica cómo comprobar aislamiento, purgas y restauración antes de usar datos reales. El [aviso de privacidad](docs/aviso-de-privacidad.md) sigue pendiente de revisión.

## Abrir la vista visual

Requiere Python 3.12 y `uv`. Desde `backend/`:

```powershell
uv sync --all-groups
uv run pytest
$env:METAGUARD_ENVIRONMENT = "development"
uv run uvicorn metaguard_api.main:app --host 127.0.0.1 --port 8000
```

En otra terminal, desde `frontend/` con Node.js y npm:

```powershell
npm ci
npm run dev
```

Abre la dirección que muestra Vite. Para comprobar la API por separado, abre `http://127.0.0.1:8000/health/live`; no requiere base de datos. `/health/ready` solo comprueba conectividad PostgreSQL, no el esquema ni el procesador. Para comprobar la interfaz, ejecuta `npm test`. El [contrato de la API](docs/api.md) distingue rutas implementadas de funciones pendientes.

La interfaz tiene vistas independientes de Inicio, Cómo funciona, Archivos y reportes, Cuenta y Privacidad. Sigue admitiendo los enlaces de sección anteriores (por ejemplo `/#cuenta` y `/#demostracion`). La actividad en `/security/events` requiere una sesión; si se abre ese enlace directamente en un servidor estático, este debe devolver la entrada del frontend para esa ruta.

## Seguridad

Mantén las [llaves y secretos](docs/llaves-y-secretos.md), los archivos de usuarios y los datos reales fuera de Git. No envíes archivos ni hashes de terceros durante las pruebas.

## Licencia

El código original de MetaGuard se ofrece bajo la [licencia MIT](LICENSE): permite usarlo, modificarlo y redistribuirlo conservando los avisos de autoría y licencia, sin garantía. Las dependencias y los materiales de terceros conservan sus propias licencias. Esta licencia no autoriza el uso de cuentas, credenciales ni archivos personales.
