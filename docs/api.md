# API REST — contrato vigente

MetaGuard implementa sondas, autenticación, MFA TOTP, carga y análisis, reportes y descarga. La aplicación sin composición de runtime solo sirve para las sondas y el OpenAPI de desarrollo: las rutas funcionales requieren dependencias configuradas y devuelven `503` si faltan. Consulta la [guía local](desarrollo-local.md) para probarlas con datos sintéticos.

## Rutas implementadas

| Método y ruta | Acceso y comportamiento |
|---|---|
| GET `/health/live` | Pública: devuelve `{"status":"ok"}` sin consultar dependencias. |
| GET `/health/ready` | Pública: ejecuta `SELECT 1` con conexión acotada y devuelve `ok` (200) o `unavailable` (503). No prueba el esquema ni el procesador. |
| GET `/v1/auth/status` | Inicializa CSRF; comprueba una sesión existente. Devuelve `authenticated` y `csrf_token`. Si se envía `Origin`, debe estar permitido. |
| POST `/v1/auth/register` | Origen y CSRF preautenticación; validación de contraseña y remitente inyectados. |
| POST `/v1/auth/verify-email` | Origen y CSRF preautenticación; código de un solo uso en el cuerpo JSON. |
| POST `/v1/auth/resend-verification` | Origen y CSRF preautenticación; correo y contraseña de la cuenta pendiente; límites por IP e identidad. |
| POST `/v1/auth/password-reset/request` | Origen y CSRF; solicita un código para un correo verificado, sin revelar si existe ni si se envió el mensaje. |
| POST `/v1/auth/password-reset/confirm` | Origen y CSRF; código de correo, contraseña nueva y segundo factor cuando está configurado. No inicia sesión. |
| GET `/v1/security/events` | Sesión activa, origen y CSRF de esa sesión. Devuelve solo los eventos del titular. |
| POST `/v1/users/me/password` | Sesión, origen, CSRF y contraseña actual; aplica la política de contraseña y revoca sesiones y desafíos activos. |
| POST `/v1/auth/login` | Origen y CSRF preautenticación; contraseña; inicia una sesión o devuelve un desafío MFA. |
| POST `/v1/auth/login/mfa` | Origen y CSRF; desafío firmado ligado al CSRF. Revalida contraseña y TOTP. |
| POST `/v1/auth/login/email` | Origen y CSRF; cuando se solicita verificación adicional por correo, revalida contraseña y un código ligado al navegador y a la dirección de origen. |
| POST `/v1/auth/logout` | Sesión, origen y CSRF; revoca la sesión en la base de datos. |
| POST `/v1/users/me/totp/setup` | Sesión, origen y CSRF; reautenticación con la contraseña para preparar el TOTP. |
| POST `/v1/users/me/totp/confirm` | Sesión, origen y CSRF; confirma el TOTP, emite códigos de recuperación y revoca sesiones. |
| POST `/v1/auth/mfa/recovery/setup` | Desafío MFA activo, origen y CSRF; contraseña y código de recuperación. Prepara un TOTP nuevo sin sustituir el anterior. |
| POST `/v1/auth/mfa/recovery/confirm` | Mismos controles más token de preparación y código TOTP nuevo. Reemplaza el factor y revoca sesiones. |
| POST `/v1/uploads` | Sesión, origen y CSRF; bytes crudos JPEG, PNG o PDF y verificación del límite durante la lectura. |
| POST `/v1/analyses/{upload_id}` | Sesión, origen, CSRF y propiedad de la carga. Procesador aislado y consentimiento opcional de VirusTotal. |
| GET `/v1/reports` | Sesión, origen y CSRF; solo reportes vigentes propios. |
| GET `/v1/reports/{report_id}` | Sesión, origen, CSRF y propiedad del reporte. |
| DELETE `/v1/reports/{report_id}` | Sesión, origen, CSRF y propiedad; elimina el reporte y retira la copia limpia. |
| POST `/v1/reports/{report_id}/download-token` | Sesión, origen, CSRF y propiedad; emite un token opaco de un uso. |
| POST `/v1/downloads` | Sesión, origen, CSRF y propiedad; token solo en JSON, respuesta binaria sin caché. |

Las rutas funcionales usan límites inyectados. La demo contabiliza intentos en memoria por proceso; por ejemplo, el registro admite como máximo cinco por hora por IP con la configuración predeterminada y la recuperación MFA comparte una ventana de cinco intentos por cuenta cada quince minutos, además del límite por IP. No equivale al bloqueo progresivo o distribuido contemplado en [límites](limites.md). CORS permite credenciales únicamente para los orígenes configurados.

## Registro y sesiones

Para solicitudes válidas, tanto un correo nuevo como uno ya registrado reciben `202` con `{"registered":true}` y `Cache-Control: no-store`. La respuesta indica recepción, no creación de cuenta ni entrega de correo. Repetir el registro no modifica cuentas existentes ni vuelve a enviar el código. No se garantiza un tiempo de respuesta idéntico. `POST /v1/auth/verify-email` recibe `{"token":"<código>"}` y, si lo consume correctamente, devuelve `{"verified":true}`.

El código se entrega únicamente al servicio de envío y se persiste como digest. En la demo se usa un capturador SMTP de loopback; Gmail es un [adaptador separado](correo-verificacion.md). El envío de registro se invoca dentro de la transacción, antes del commit. Un error de envío revierte la cuenta y el token; una aceptación SMTP seguida de un fallo de commit no se puede deshacer y no hay cola transaccional.

Para un código perdido o vencido, el reenvío recibe `{"email":"<correo>","password":"<contraseña original>"}` y devuelve `202 {"requested":true}` en los intentos admitidos. Solo se intenta enviar para una cuenta pendiente con contraseña correcta. Un fallo de envío no cambia el código anterior. Los límites locales son de un intento por identidad por minuto, cinco por hora por identidad y una cuota por IP basada en el límite de registro configurado. La aceptación no garantiza entrega ni oculta diferencias de latencia.

El cambio autenticado de contraseña recibe `{"current_password":"<actual>","new_password":"<nueva>"}`. Al confirmar devuelve `200 {"changed":true}`, elimina las cookies de esa sesión y revoca las sesiones y los desafíos MFA anteriores. No altera el autenticador ni los códigos de respaldo. **No es restablecimiento de contraseña olvidada.**

Para restablecer una contraseña olvidada, la solicitud recibe `{"email":"<correo>"}` y devuelve `202 {"requested":true}` para las solicitudes válidas admitidas, sin consultar la cuenta antes de responder. El trabajo de correo posterior es limitado y no garantiza entrega. Los códigos son aleatorios (128 bits), de un uso y vencen en 15 minutos; se guarda solo su huella vinculada a la versión de contraseña. La confirmación recibe `{"email":"<correo>","code":"<32 caracteres hexadecimales>","new_password":"<nueva>","mfa_code":"<TOTP o respaldo>"}`. El campo `mfa_code` se puede omitir si la cuenta no tiene MFA. Los intentos se limitan por IP e identidad independientemente de la existencia de una cuenta. Un código de respaldo solo puede probar un restablecimiento y sigue disponible para la ceremonia separada de reemplazo del autenticador; esa ceremonia retira los códigos anteriores.

Una confirmación válida devuelve `200 {"changed":true}`, invalida todos los códigos pendientes y revoca las sesiones y desafíos anteriores en la misma transacción. El TOTP no se reemplaza ni se desactiva. Las respuestas no se almacenan en caché y no se incluyen códigos en las URLs. Los códigos correctos y un segundo factor válido no eximen de la política de contraseñas. El [flujo de cuenta](recuperacion-de-cuenta.md) explica cómo volver a iniciar sesión.

El JWT HS256 y el CSRF independiente usan cookies host-only `Secure` y `HttpOnly`. El CSRF también vuelve en JSON para uso en memoria; el JWT nunca. Por defecto se usa `SameSite=Lax`; `None` exige orígenes exactos y sigue usando `Secure`. La verificación de sesión consulta su fila en PostgreSQL, que conserva solo los digests del JWT y del CSRF. El cierre confirmado invalida usos posteriores de esa sesión. Ver [sesiones opacas](sesiones-opacas.md).

### Alta y recuperación de MFA

| Ruta | Cuerpo JSON | Respuesta 200 |
|---|---|---|
| `/v1/users/me/totp/setup` | `{password}` | `{secret, otpauth_uri, expires_at}` |
| `/v1/users/me/totp/confirm` | `{code}` | `{recovery_codes}` |
| `/v1/auth/mfa/recovery/setup` | `{email, password, recovery_code}` | `{secret, otpauth_uri, expires_at, setup_token}` |
| `/v1/auth/mfa/recovery/confirm` | `{email, password, recovery_code, setup_token, code}` | `{recovery_codes}` |

`expires_at` es una marca UNIX en segundos UTC. La semilla solo se entrega para configurar el autenticador del usuario; no debe enviarse a un servicio de QR. `code` contiene los seis dígitos del autenticador. `recovery_code` es uno de los ocho códigos de 32 caracteres hexadecimales mostrados una vez al confirmar el alta o el reemplazo. La recuperación exige primero el desafío emitido por `/v1/auth/login` con la contraseña; no admite correo o contraseña como único factor.

Todas las respuestas de autenticación y TOTP llevan `Cache-Control: no-store`. Tras confirmar el alta o el reemplazo, se revocan las sesiones, se borran las cookies de autenticación, CSRF y desafío y se necesita volver a iniciar sesión con un TOTP del siguiente intervalo. El reemplazo invalida los códigos anteriores sin desactivar MFA. Ver [recuperación de cuenta](recuperacion-de-cuenta.md).

## Archivos, reportes y descarga

- **Carga.** Envía bytes crudos, no multipart, con `Content-Type: image/jpeg`, `image/png` o `application/pdf`. El original se cifra en memoria y se vincula a su dueño y tipo.
- **Análisis.** Envía un objeto JSON con `virus_total_consent` (booleano estricto, predeterminado `false`). La API usa el cliente IPC hacia el [procesador aislado](procesamiento-archivos.md), no procesa el archivo en FastAPI.
- **Reportes.** Análisis y detalle devuelven `{report_id, report, created_at, expires_at}`; el listado devuelve `{reports: [...]}`. La proyección de `report` contiene solo `media_type`, `metadata_categories`, `output_verified`, `width`, `height`, `page_count`, `active_content_removed` y `uri_links_removed`. No se conservan ni devuelven los valores de los metadatos extraídos.
- **Descarga.** La emisión retorna `{"token":"<opaco>","expires_at":"<UTC ISO-8601>"}`. Envía `{"token":"<opaco>"}` a `POST /v1/downloads` con `Content-Type: application/json`. Nunca incluyas el token en la URL ni registres el cuerpo. La API guarda solo el digest y lo consume de forma atómica. El binario se devuelve con `Content-Type` permitido, `Content-Disposition: attachment` y `Cache-Control: no-store`.

### Consulta de reputación

La respuesta inmediata de análisis incluye `virus_total` con entradas `original` y `cleaned`. Cada una contiene `status`, `last_analysis_stats`, `last_analysis_date` y `report_url`. El estado puede ser `found`, `not_found`, `not_requested`, `rate_limited`, `key_unavailable` o `unavailable`.

Solo con consentimiento explícito y proveedor habilitado se consultan los SHA-256 del original y de la copia limpia, nunca el archivo. La cuota persistida es de 4 consultas por 60 segundos y 500 por día UTC; la caché de reputación es independiente y no se vincula a la cuenta. El resultado no se guarda en los reportes del usuario ni condiciona la limpieza. Un resultado sin detecciones no prueba que el archivo sea seguro. La demo desactiva el proveedor.

### Retención y purga

Original y copia limpia expiran a los diez minutos de su creación respectiva. La descarga exitosa o el borrado del reporte retira la copia limpia; el token nunca dura más que esa copia. Los reportes expiran a las 24 horas. La tarea automática arranca solo en una composición con runtime de archivos, almacén de memoria y base de datos; purga filas vencidas y el almacén del proceso. El comando de mantenimiento separado solo puede limpiar la base de datos. Esto no garantiza durabilidad entre procesos ni borrado físico. Ver [inventario y retención](datos.md).

## Contraseñas y dependencias

El registro aplica un mínimo de 15 caracteres y una lista local proporcionada por quien configura la API. Cuando se habilita el [transporte de Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords), este consulta solo el prefijo SHA-1 de cinco caracteres sobre HTTPS y solicita padding; la comparación es local. Ante indisponibilidad, el registro solo sigue si pasa la política local y se puede guardar un evento genérico en una transacción independiente. Las respuestas inválidas, truncadas o que exceden los límites no habilitan el respaldo. La demo deshabilita la conexión a HIBP y exige la lista local para registrar cuentas; esa protección reducida no equivale a cotejar brechas.

## Errores y alcance pendiente

- `400`: solicitud inválida; `401`: credencial o sesión inválida; `403`: origen o CSRF no válido; `404`: recurso ausente, vencido o ajeno; `409`: estado incompatible.
- `413`: tamaño excedido; `415`: tipo no admitido; `429`: cuota excedida; `503`: dependencia o capacidad no disponible. No registrar ni reflejar contraseñas, códigos, cookies, llaves o contenido de archivos.
- **Sin implementar:** baja de cuenta, desactivación de TOTP y refresh de sesión. El diagnóstico interno de falla de la comprobación de contraseñas no es un registro de eventos por usuario.

## Actividad de seguridad

`GET /v1/security/events` devuelve `{"events":[{"kind":"login_failed","created_at":"2026-11-21T12:00:00Z"}]}` en orden del más reciente, con hasta 50 eventos de los últimos 30 días. La identidad se obtiene de la sesión; la ruta no acepta un selector de cuenta ni incluye ID, correo, IP, nombre de archivo o valores de metadatos. La respuesta lleva `Cache-Control: no-store`. La demo web necesita la regla exacta de origen del proxy HTTPS local para esa lectura, además del CSRF de la sesión; un proxy real requiere su propia validación.

La versión actual registra intentos fallidos de contraseña y MFA, discrepancias confirmadas entre formato declarado y tipo admitido, cuotas cuando se conoce el titular, contenido activo señalado por la inspección de PDF y contraseñas filtradas rechazadas en cambios con identidad comprobada. La política de inicio de sesión agrega `new_ip_login` después de un acceso exitoso desde una dirección no vista recientemente; el primer acceso establece la referencia. Cada tipo se agrupa por cuenta en ventanas de diez minutos. No se equipara una detección con acceso confirmado ni con un veredicto sobre malware.

Con la política de inicio de sesión habilitada, cinco fallos del mismo par cuenta/dirección provocan un bloqueo temporal de 1, 5 o 15 minutos según el tramo; no se bloquea la cuenta en todas las direcciones. Si hay fallos desde al menos tres direcciones en quince minutos y la contraseña es correcta, se exige la prueba TOTP existente o, sin TOTP, una verificación adicional por correo. En ese caso `POST /v1/auth/login` devuelve `{"authenticated":false,"email_challenge_required":true,"csrf_token":"…"}` sin sesión. `POST /v1/auth/login/email` recibe `{"email":"<correo>","password":"<contraseña>","code":"<32 caracteres hexadecimales>"}`. El código dura cinco minutos, admite un uso y no sirve para verificar ni restablecer la cuenta.

El bloqueo, el incremento de riesgo entre direcciones o un acceso válido desde una dirección nueva pueden programar una alerta genérica. La cola limita, agrupa y reintenta; el despachador solo funciona con un remitente explícito. El ensayo SMTP local no acredita entrega pública. Antes de habilitar la política en otro entorno, validar allí la procedencia de la dirección y el remitente dedicado.
- El OpenAPI está disponible en desarrollo en `/openapi.json` y `/docs`; no prueba disponibilidad de dependencias ni preparación para producción. Para evidencia de despliegue, consulta la [guía de staging](validacion-staging.md).
