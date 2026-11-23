# Probar MetaGuard en desarrollo local

Usa la fábrica `metaguard_api.local_runtime:create_local_app` para conectar la autenticación a una base PostgreSQL descartable. El punto de entrada habitual `metaguard_api.main:app` sigue siendo útil para comprobar que la API responde, pero no habilita sesiones ni procesamiento por sí solo. Usa solo datos sintéticos: esta configuración no es un despliegue.

Antes de empezar, confirma que Python 3.12 o posterior, `uv`, Node.js, npm y las dependencias fijadas ya estén disponibles. La [vista visual](../README.md#abrir-la-vista-visual) muestra la preparación de dependencias; los comandos `uv` de esta guía no sincronizan ni descargan. Los bloques usan PowerShell 7, también disponible en Linux. Para una presentación, sigue el [guion de entrega académica](entrega-academica.md).

## 1. Preparar PostgreSQL y las llaves

Necesitas una instancia de PostgreSQL que escuche **solo en loopback**, una base descartable **`metaguard_test`** y un usuario local que pueda aplicar sus migraciones. El puerto `55432` del ejemplo es el de una instancia separada: cámbialo si tu instancia de prueba usa otro. Guarda la contraseña de PostgreSQL en un archivo `postgres_password` en un directorio fuera del repositorio, con acceso restringido a tu usuario.

Desde `backend/` en PowerShell, configura el destino y verifica que no haya sustituciones de destino de libpq:

```powershell
$env:METAGUARD_DB_HOST = '127.0.0.1'
$env:METAGUARD_DB_PORT = '55432'
$env:METAGUARD_DB_NAME = 'metaguard_test'
$env:METAGUARD_DB_USER = 'metaguard'
$env:METAGUARD_DB_SECRET_DIR = Read-Host 'Directorio protegido de secretos de la instancia descartable'
if ((Test-Path Env:PGHOSTADDR) -or (Test-Path Env:PGSERVICE)) {
    throw 'Quita las sustituciones de destino PGHOSTADDR y PGSERVICE de esta terminal.'
}
if ((-not $env:METAGUARD_DB_SECRET_DIR) -or
    (-not (Test-Path -LiteralPath (Join-Path $env:METAGUARD_DB_SECRET_DIR 'postgres_password') -PathType Leaf))) {
    throw 'Falta el archivo de contraseña de la instancia de pruebas.'
}
uv run --offline --no-sync alembic upgrade head
if ($LASTEXITCODE -ne 0) { throw 'No se aplicó la migración.' }
uv run --offline --no-sync alembic current
if ($LASTEXITCODE -ne 0) { throw 'No se pudo consultar la versión del esquema.' }
```

La fábrica también acepta el destino PostgreSQL literal `::1`; no acepta nombres DNS ni bases con otro nombre. No ejecuta migraciones automáticamente. **El nombre de la base no comprueba que sea descartable**: verifica el puerto y que la instancia no contenga datos reales antes de migrar.

Crea dos llaves exclusivas del entorno de prueba, en un directorio nuevo y privado fuera del repositorio. Conserva el directorio mientras quieras reutilizar las mismas llaves:

```powershell
$privateRoot = if ($IsWindows) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/share' }
$env:METAGUARD_SECRET_DIR = Join-Path $privateRoot ('MetaGuard/local-auth-' + [guid]::NewGuid().ToString('N'))
@'
import os
from pathlib import Path
from secrets import token_bytes, token_urlsafe

root = Path(os.environ["METAGUARD_SECRET_DIR"])
root.mkdir(mode=0o700, parents=True, exist_ok=False)
with (root / "jwt_signing_key").open("x", encoding="utf-8") as handle:
    handle.write(token_urlsafe(32))
with (root / "totp_encryption_key").open("xb") as handle:
    handle.write(token_bytes(32))
'@ | uv run --offline --no-sync python -
if ($LASTEXITCODE -ne 0) { throw 'No se crearon las llaves de desarrollo.' }
```

En Windows, asegúrate de que la carpeta herede permisos privados de tu perfil. No agregues ningún archivo generado al repositorio ni muestres su contenido. No reutilices estas llaves en producción.

## 2. Iniciar el backend y el frontend

Si necesitas registrar una cuenta nueva, configura primero el capturador y la lista del paso 3 en la misma terminal. Si también vas a analizar archivos, configura el procesador del paso 4 antes de arrancar la API.

En la terminal del backend:

```powershell
$env:METAGUARD_ENVIRONMENT = 'development'
$env:METAGUARD_AUTH_ALLOWED_ORIGINS = '["https://127.0.0.1:5173"]'
$env:METAGUARD_LOCAL_VIRUS_TOTAL_ENABLED = 'false'
uv run --offline --no-sync uvicorn metaguard_api.local_runtime:create_local_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers --no-access-log
```

Conserva una instancia y no habilites las cabeceras de proxy; la API local limita el acceso al peer de loopback. El navegador llega al backend HTTP a través del proxy local del frontend. La app exige cookies `Secure` y `HttpOnly`: no desactives esa protección.

En una segunda terminal, desde `frontend/`, configura rutas de archivos PEM de un certificado local con una cadena que tu navegador ya confíe. Incluye la IP `127.0.0.1` en el SAN del certificado. No guardes la llave TLS en el repositorio:

```powershell
$env:METAGUARD_DEV_TLS_CERT = Read-Host 'Ruta del certificado PEM local'
$env:METAGUARD_DEV_TLS_KEY = Read-Host 'Ruta de la llave PEM local protegida'
npm run dev -- --port 5173 --strictPort
```

Abre `https://127.0.0.1:5173`. La comprobación de base de datos indica conectividad, no comprueba el esquema ni el procesador. Para iniciar sesión necesitas una cuenta de prueba ya verificada o habilitar el registro local del paso siguiente. El proxy HTTPS de Vite completa la cabecera `Origin` que el navegador omite en las consultas GET de reportes por HTTPS del mismo origen, tanto en HTTP/1.1 como en HTTP/2. En las descargas por POST se conserva la cabecera `Origin` enviada por el navegador. La API comprueba el origen, el CSRF y la sesión en ambos casos. No uses este proxy como servidor de producción.

### Si una función nueva devuelve 404

Un `401` al reutilizar un código o al entrar con una contraseña anterior es un rechazo esperado. Un `404` en una ruta del contrato puede indicar que Vite apunta a un backend anterior. Antes de cambiar o bloquear una cuenta, revisa el esquema activo de desarrollo sin enviar credenciales:

```powershell
$schema = Invoke-RestMethod 'http://127.0.0.1:8000/openapi.json'
$schema.paths.PSObject.Properties.Name | Where-Object { $_ -match 'password-reset|resend-verification|security/events|users/me/password|auth/login/email' }
```

Si faltan esas rutas, descarga primero cualquier copia limpia pendiente: **la API pierde archivos temporales en memoria al reiniciar**. Solo para una base de demo descartable y confirmada, aplica el paso 1 desde la copia actual y vuelve a arrancar el backend con el paso 2. Repite la consulta del esquema. No migres bases reales por esta comprobación. `/health/live` y `/health/ready` pueden dar `200` en un proceso anterior y no sustituyen este control. La API de producción no expone OpenAPI por defecto.

## 3. Habilitar el registro de prueba (opcional)

Antes de arrancar el backend, prepara un **capturador SMTP local sin relay**, que escuche en `127.0.0.1`. No uses un proveedor de correo ni datos reales. Configura ambos valores:

```powershell
$env:METAGUARD_LOCAL_SMTP_PORT = '1025'
$env:METAGUARD_LOCAL_PASSWORD_BLOCKLIST = Read-Host 'Ruta de una lista local de contraseñas bloqueadas'
```

La lista debe ser un archivo UTF-8 no vacío, de hasta 1 MiB, con una contraseña por línea. Registra una cuenta sintética `usuario@example.test`, recupera el token desde el capturador local, pégalo en el formulario de verificación e inicia sesión. El token no se devuelve en respuestas del API. La consulta HIBP está deshabilitada en este modo: la API aplica la lista local y registra un evento genérico de protección reducida. Si falta la configuración, el registro no se habilita.

**Prueba MFA.** Con la sesión iniciada, abre la configuración del autenticador. Confirma tu contraseña, agrega la clave a una aplicación TOTP sin compartirla y confirma el código actual. Guarda los ocho códigos de respaldo fuera de MetaGuard: solo se muestran una vez. Vuelve a iniciar sesión con un código del siguiente intervalo TOTP.

**Si pierdes el autenticador**, inicia sesión con la contraseña y selecciona la recuperación en el paso MFA. Utiliza un código de respaldo y confirma un código del nuevo autenticador. Solo después de la confirmación se reemplaza el dispositivo, se invalidan los códigos anteriores y se revocan las sesiones. No hay recuperación por correo. Usa exclusivamente cuentas de prueba.

Los límites locales contabilizan intentos en memoria de un proceso, se reinician al cerrarlo y no equivalen al bloqueo progresivo de producción.

### Probar actividad y correo de seguridad

En una base sintética con migraciones hasta `0016_login_email_challenge`, inicia sesión y abre **Ver actividad de seguridad**. No introduzcas los códigos del capturador en registros o capturas de la entrega. El runtime local activa la protección de inicio de sesión; configura el capturador para ensayar verificaciones adicionales por correo y alertas. Sin capturador, una cuenta sin TOTP que necesite verificación adicional no obtiene sesión: no se omite la prueba por un fallo de configuración.

Desde `backend`, estas pruebas reproducen decisiones de inicio de sesión y la entrega de una alerta a un SMTP de loopback separado. No usan la base de la demo, correo real ni tráfico de carga:

```powershell
uv run --offline --no-sync pytest -q --no-cov tests/test_login_risk_routes.py tests/test_security_alert_workflow.py
```

El proxy HTTPS de desarrollo habilita la lectura exacta de `/v1/security/events`; no sirve como prueba del punto de entrada público.

## 4. Habilitar archivos en Linux (opcional)

No hay procesamiento aislado en Windows nativo. En Linux, configura el [servicio privado de procesamiento](procesamiento-archivos.md#run-the-private-listener-on-linux) para escuchar en un socket Unix protegido, bajo un UID no privilegiado distinto al de la API. Proporciona a la API `METAGUARD_LOCAL_PROCESSOR_SOCKET` (ruta absoluta) y `METAGUARD_LOCAL_PROCESSOR_UID` (UID efectivo del servicio). Agrega un archivo `data_encryption_key` con 32 bytes aleatorios binarios, independiente de la llave TOTP, en el directorio configurado de secretos de la API. Si usas WSL, ejecuta la API y el servicio en el entorno Linux que comparte el socket; no apuntes el backend nativo de Windows a ese socket.

La fábrica conecta el cliente IPC existente sin ejecutar Docker ni analizar archivos en el proceso HTTP. Requiere un servicio separado correctamente configurado; sin él no hay análisis ni descarga funcional. Los reportes persistidos y los archivos temporales del proceso tienen un ciclo de purga, pero no se garantiza el borrado físico ni que los archivos en memoria sobrevivan a un reinicio.

La purga automática se inicia solo con el runtime de archivos, un almacén `InMemoryTemporaryFileStore` y una base `Database` configurados. Se ejecuta al arrancar y espera 60 segundos entre ciclos; limpia filas vencidas de reportes, eventos de sistema y caché de reputación, y también los archivos temporales del proceso. El comando de mantenimiento de base de datos no puede purgar la memoria de otro proceso. Esto no sustituye las pruebas de retención en staging.

**Para la demo, deja VirusTotal desactivado** y la casilla de consentimiento sin marcar. Una prueba separada con autorización explícita requiere un procesador configurado, consentimiento por archivo y una credencial en el directorio protegido del API, según [llaves y secretos](llaves-y-secretos.md#virustotal-fuera-de-la-demo). Ni el registro local ni la demostración necesitan Gmail o HIBP en línea.
