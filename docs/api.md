# API REST — contrato inicial propuesto

**Propósito:** fijar rutas/controles para OBJ-02. **Estado:** contrato inicial; solo `/health/live` se implementó en el esqueleto de API. Las 18 rutas funcionales no están implementadas. El OpenAPI actual solo incluye liveness y no equivale a este contrato completo. JSON salvo cuerpo binario de subida/descarga.

## Rutas

Las tasas generales, de registro, de carga y el bloqueo progresivo documentados en `docs/limites.md` fueron aprobados solo para demo; aún requieren pruebas y no se consideran producción. Los límites adicionales por endpoint de esta tabla son candidatos pendientes de aprobación. Mutaciones con cookie JWT requieren protección CSRF. La API debe aplicar autorización por objeto a cada `user_id`/recurso.

| Método | Ruta | Auth / control | Límite inicial | Errores principales |
|---|---|---|---|---|
| GET | `/health/live` | Pública; solo indica que el proceso API responde, sin detalles de dependencias/secretos | Sonda local del runtime | 200 |
| POST | `/v1/auth/register` | Pública; validar entrada | 5/h/IP | 400, 409, 422, 429, 503 |
| POST | `/v1/auth/login` | Pública; requiere token CSRF preauth de same-origin y valida `Origin`; inicia contraseña | 5 fallos por cuenta+IP antes de bloqueo progresivo | 400, 401, 403, 429 |
| POST | `/v1/auth/login/mfa` | Etapa de login con desafío preauth firmado y CSRF; no acepta JWT aún | 5 intentos/cuenta+IP | 401, 403, 429 |
| GET | `/v1/auth/status` | Pública; respuesta mínima, no filtra perfil; emite nonce CSRF preauth | 60/min/IP | 429 |
| POST | `/v1/auth/logout` | JWT cookie + CSRF | 60/min/cuenta | 401, 403 |
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

Son 18 rutas funcionales candidatas, más la sonda operacional `/health/live`. Registro, login y status son públicas con tasa limitada; login/status entregan o exigen un nonce CSRF preauth y validación de origen para impedir que otro sitio cree una sesión en el navegador de la víctima. La sonda solo informa `ok` y no consulta DB ni secretos. La etapa MFA solo acepta desafío preautenticado, CSRF y tasa limitada. La expiración exacta del JWT corto, formato del desafío MFA, contrato final de CSRF y paginación siguen pendientes. El endpoint de descarga exige simultáneamente sesión JWT, propiedad del recurso y token de un uso; el token por sí solo no autoriza acceso.

## Dependencias externas de contraseña y fallas

Al registrar/cambiar contraseña, HIBP recibe únicamente prefijo SHA-1 de 5 caracteres con padding; la comparación se hace local. Si HIBP no responde, la propuesta U2 exige fallback local: comprobar longitud mínima y lista local de contraseñas comunes, registrar evento de falla del servicio y comunicar que la protección queda reducida (no equivale a cotejar brechas). El registro/cambio continúa solo si pasa la política local. Prueba pendiente: simular timeout/5xx, comprobar fallback y evento, y verificar que nunca salen contraseña ni hash completo.

VirusTotal es opcional por archivo; si no está disponible o se vence la consulta, informar “no disponible/sin antecedentes conocido no equivale a seguro” y no bloquear limpieza. SMTP puede fallar: registrar falla sin afirmar que se entregó la alerta; política de reintento/cola está pendiente.

## Errores y reglas comunes

- `400` formato inválido; `401` sin sesión/credencial válida; `403` CSRF/origen/permiso; `404` recurso ausente o ajeno (sin revelar su existencia); `409` estado/ciclo incompatible.
- `413` archivo demasiado grande; `415` tipo no permitido; `422` campos inválidos; `429` cuota excedida con `Retry-After`; `503` servicio necesario temporalmente no disponible.
- Respuesta de error genérica, con ID de correlación aleatorio; nunca stack trace, ruta del servidor, contenido, token, contraseña o llave.
- HTTPS obligatorio. API confía solo en cabeceras de IP saneadas por Nginx. Validar tipos/tamaños, autorización y límites antes de cambiar estado.

## Qué pasa si falta

Sin contrato y matriz de acceso, frontend/backend pueden divergir y los recursos de un usuario pueden quedar expuestos por IDOR. Antes de implementación, generar OpenAPI y pruebas de cada permiso.
