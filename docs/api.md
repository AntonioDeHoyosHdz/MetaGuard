# API REST — contrato inicial propuesto

La composición interna de contraseña y TOTP requiere una sesión sin cambios ORM pendientes y devuelve un identificador provisional únicamente después de verificar ambos factores. El llamador debe confirmar la transacción antes de conceder acceso. Esta función privada no crea sesiones ni implementa una ruta, CSRF, límites de intentos o recuperación; su comportamiento concurrente aún requiere pruebas con PostgreSQL real.

**Propósito:** fijar rutas/controles para OBJ-02. **Estado:** contrato inicial; las sondas `/health/live` y `/health/ready` y las cuatro rutas de auth están implementadas, pero auth responde `503` si el llamador no inyecta base de datos, llaves y rate limiter. Las otras 14 rutas funcionales no están implementadas. Esto no declara preparación para producción; el OpenAPI actual no equivale al contrato completo. JSON salvo cuerpo binario de subida/descarga.

La primitiva privada de sesión emite JWT HS256 con llave, issuer, audience, `now` UTC y vencimiento suministrados por el llamador. La llave debe ser criptográficamente aleatoria y tener al menos 32 bytes UTF-8; el llamador confiable debe provisionarla. Solo persiste digests SHA-256 del JWT y del token CSRF independiente. Las rutas de auth usan cookies host-only `HttpOnly` y `Secure`, nunca devuelven el JWT en JSON y consultan la fila por solicitud autenticada; el logout confirmado invalida de inmediato validaciones posteriores al commit. El detalle de este compromiso está en `docs/sesiones-opacas.md`.

## Rutas

Las tasas generales, de registro, de carga y el bloqueo progresivo documentados en `docs/limites.md` fueron aprobados solo para demo; aún requieren pruebas y no se consideran producción. Los límites adicionales por endpoint de esta tabla son candidatos pendientes de aprobación. Mutaciones con cookie JWT requieren protección CSRF. La API debe aplicar autorización por objeto a cada `user_id`/recurso.

| Método | Ruta | Auth / control | Límite inicial | Errores principales |
|---|---|---|---|---|
| GET | `/health/live` | Pública; solo indica que el proceso API responde, sin detalles de dependencias/secretos | Sonda local del runtime | 200 |
| GET | `/health/ready` | Pública; consulta mínima de PostgreSQL, sin detalles de errores y sin caché | Sonda local del runtime | 200, 503 |
| POST | `/v1/auth/register` | Pública; validar entrada | 5/h/IP | 400, 409, 422, 429, 503 |
| POST | `/v1/auth/login` | Requiere Origin exacto, CSRF preauth y limiter inyectado; contraseña | Configurado por el llamador | 400, 401, 403, 429, 503 |
| POST | `/v1/auth/login/mfa` | Desafío firmado, de un solo uso y ligado al CSRF que lo emitió; revalida contraseña y TOTP | Configurado por el llamador | 401, 403, 429, 503 |
| GET | `/v1/auth/status` | Respuesta mínima; verifica sesión DB; devuelve CSRF JSON y cookie HttpOnly | Configurado por el llamador | 403, 429, 503 |
| POST | `/v1/auth/logout` | JWT cookie + CSRF + Origin exacto; revocación DB | Configurado por el llamador | 401, 403, 429, 503 |
| POST | `/v1/users/me/password` | JWT + CSRF + contraseña actual | 5/h/cuenta | 400, 401, 429, 503 |
| POST | `/v1/users/me/totp/setup` | JWT + CSRF; reautenticación | 5/h/cuenta | 401, 403, 409, 429 |
| POST | `/v1/users/me/totp/confirm` | JWT + CSRF + código TOTP | 5 intentos/15 min/cuenta | 400, 401, 429 |
| DELETE | `/v1/users/me/totp` | JWT + CSRF + reautenticación | 5/h/cuenta | 401, 403, 429 |
| DELETE | `/v1/users/me` | JWT + CSRF + reautenticación | 1/h/cuenta | 401, 403, 429 |
| POST | `/v1/uploads` | JWT + CSRF; stream, no parsear en API | 3/min/IP; 10/h/cuenta | 400, 401, 413, 415, 429 |
| POST | `/v1/analyses/{upload_id}` | JWT + CSRF + dueño del upload; consentimiento VT por archivo | 10/h/cuenta | 401, 403/404, 409, 429, 503 |
| GET | `/v1/reports` | JWT; solo reportes propios | 60/min/cuenta | 401, 429 |
| GET | `/v1/reports/{report_id}` | JWT + dueño del reporte | 60/min/cuenta | 401, 404, 429 |
| DELETE | `/v1/reports/{report_id}` | JWT + CSRF + dueño del reporte | 10/min/cuenta | 401, 404, 429 |
| GET | `/v1/security/events` | JWT; solo eventos propios | 60/min/cuenta | 401, 429 |
| POST | `/v1/reports/{report_id}/download-token` | JWT + CSRF + dueño; emite token de un uso | 10/h/cuenta | 401, 404, 409, 429 |
| GET | `/v1/downloads/{token}` | JWT + dueño del recurso + token válido de un uso; vence en 10 min | 60/min/IP | 401, 403/404, 410, 429 |

Son 18 rutas funcionales candidatas, además de las dos sondas operacionales. Las cuatro rutas de auth están implementadas detrás de dependencias inyectadas: una sesión DB, llaves y un rate limiter; sin ellas responden fail-closed con `503`. Los orígenes permitidos deben ser exactos, CORS permite credenciales solo para esa lista y las mutaciones exigen Origin y CSRF coincidentes. Las cookies JWT y CSRF son `HttpOnly`, `Secure`, host-only; el token CSRF también vuelve solo en JSON para uso en memoria. `SameSite=Lax` es el valor predeterminado; `None` requiere orígenes exactos y siempre se emite con `Secure`. No hay ruta de refresh ni claim de preparación para producción. Las otras 14 rutas siguen pendientes. `/health/live` solo informa `ok` y no consulta DB ni secretos. El endpoint de descarga exige simultáneamente sesión JWT, propiedad del recurso y token de un uso; el token por sí solo no autoriza acceso.

`/health/ready` ejecuta `SELECT 1` con tiempo de conexión limitado y devuelve únicamente `ok` o `unavailable`; no confirma que existan migraciones, tablas o datos. La prueba contra PostgreSQL real sigue pendiente.

## Dependencias externas de contraseña y fallas

Al registrar/cambiar contraseña, HIBP recibe únicamente prefijo SHA-1 de 5 caracteres con padding; la comparación se hace local. Si HIBP no responde, la propuesta U2 exige fallback local: comprobar longitud mínima y lista local de contraseñas comunes, registrar evento de falla del servicio y comunicar que la protección queda reducida (no equivale a cotejar brechas). El registro/cambio continúa solo si pasa la política local. Prueba pendiente: simular timeout/5xx, comprobar fallback y evento, y verificar que nunca salen contraseña ni hash completo.

El backend incluye un transporte para [Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords): usa HTTPS, solicita padding, no sigue redirecciones y limita el tamaño de respuesta. Rechaza respuestas truncadas o sin una delimitación verificable; las respuestas no ASCII se tratan como inválidas, no como una caída que permita el fallback. Sus pruebas simulan la red y no se realizó una consulta real al servicio.

Si falla la lectura después de recibir la respuesta, o si su delimitación por bloques está incompleta o excede los límites, el registro se rechaza: no se trata como una caída apta para respaldo. Una caída al abrir la conexión o una respuesta HTTP no exitosa conserva el respaldo reducido, sujeto a las demás condiciones y al registro del evento.

El componente interno `password_policy` aplica un mínimo provisional de 15 caracteres y compara con una lista local proporcionada por el llamador antes de consultar el rango HIBP. El mínimo conservador toma como referencia [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html); no implica que ya exista autenticación. El registro privado conecta el transporte fijo y el evento genérico, registrado en una transacción independiente, y marca la protección reducida si el servicio no está disponible. Exige una sesión nueva y un pool con conexiones independientes; el llamador debe confirmar el registro antes de entregar el token. Si falla el evento o la respuesta es inválida, no devuelve éxito. **Aún no hay lista local mantenida ni registro público**; no habilitar el fallback público hasta completarlos. El componente no asegura que una lista arbitraria sea exhaustiva.

VirusTotal es opcional por archivo; si no está disponible o se vence la consulta, informar “no disponible/sin antecedentes conocido no equivale a seguro” y no bloquear limpieza. SMTP puede fallar: registrar falla sin afirmar que se entregó la alerta; política de reintento/cola está pendiente.

## Errores y reglas comunes

- `400` formato inválido; `401` sin sesión/credencial válida; `403` CSRF/origen/permiso; `404` recurso ausente o ajeno (sin revelar su existencia); `409` estado/ciclo incompatible.
- `413` archivo demasiado grande; `415` tipo no permitido; `422` campos inválidos; `429` cuota excedida con `Retry-After`; `503` servicio necesario temporalmente no disponible.
- Respuesta de error genérica, con ID de correlación aleatorio; nunca stack trace, ruta del servidor, contenido, token, contraseña o llave.
- HTTPS obligatorio. API confía solo en cabeceras de IP saneadas por Nginx. Validar tipos/tamaños, autorización y límites antes de cambiar estado.

## Qué pasa si falta

Sin contrato y matriz de acceso, frontend/backend pueden divergir y los recursos de un usuario pueden quedar expuestos por IDOR. Antes de implementación, generar OpenAPI y pruebas de cada permiso.

La migración `0005_system_security_events` agrega eventos de sistema minimizados: identificador aleatorio, tipo permitido y momento UTC, sin contraseña, correo ni IP. Una operación interna borra eventos con 30 días o más, pero todavía no está programada. El helper `record_password_check_outage` confirma el evento en una transacción independiente para que sobreviva a un fallo posterior de registro; aún no está integrado al endpoint ni probado en PostgreSQL real. Si no puede registrar el evento, el respaldo debe fallar de forma segura. Revertir la migración elimina estos eventos.

La futura integración debe comprobar la contraseña y confirmar cualquier evento de caída antes de comenzar escrituras de la cuenta; en SQLite, otra transacción escritora puede bloquear el registro independiente y debe producir fallo seguro.
