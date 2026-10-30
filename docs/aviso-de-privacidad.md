# Aviso de privacidad — borrador académico

**Propósito:** explicar al usuario qué datos trataría MetaGuard antes del registro y la carga. **Estado:** borrador; datos del responsable/contacto y revisión jurídica pendientes. No es una declaración de cumplimiento legal ni debe publicarse como aviso definitivo.

## Identidad del responsable

Responsable: **PENDIENTE de confirmar** (equipo académico / persona responsable). Domicilio y contacto para privacidad/solicitudes: **PENDIENTES**. No desplegar ni recabar datos reales antes de definirlos y revisar este borrador.

## Datos, usos y plazos propuestos por U2

| Datos | Finalidad | Plazo propuesto | Protección |
|---|---|---|---|
| Archivo original y copia limpia | Analizar y entregar descarga | Máximo 10 min; borrar al descargar o expirar | Temporal en memoria, AES-256-GCM y token de un uso. |
| Reporte (puede incluir GPS, autor, serie) | Mostrar antes/después | 24 h o borrado manual | Cifrado por campo de valores sensibles. |
| IP y eventos de seguridad | Alertar y proteger cuentas | 30 días | Acceso por usuario; minimizar contenido del evento. |
| Contraseña y TOTP | Autenticación/MFA | Mientras exista la cuenta | Contraseña Argon2id; secreto TOTP AES-256-GCM. |
| Caché de reputación | Reducir consultas externas | 24 h | Hash/veredicto, sin contenido ni vínculo con usuario. |
| Correo/identificador de cuenta | Registro y alertas | PENDIENTE de definir | Minimizar; control de acceso y protección por definir. |

## Terceros y consentimiento

- MetaGuard no pretende subir el archivo a servicios externos. HIBP recibiría únicamente prefijo SHA-1 de 5 caracteres con padding para cotejo local al crear/cambiar contraseña.
- VirusTotal se consulta solo con consentimiento expreso por archivo; se envía únicamente SHA-256 del original y de la copia limpia. El hash identifica el archivo y el proveedor puede inferir que fue consultado; no equivale a compartir cero información.
- Proveedor SMTP recibe lo mínimo necesario para entregar alertas. Proveedor, región y datos tratados están por confirmar.

## Derechos y controles del usuario

Antes de operar, definir el canal para solicitar acceso, corrección, cancelación/oposición y revocar consentimiento cuando aplique. La propuesta U2 contempla ver y eliminar cuenta, reportes y eventos. Plazos, responsable y procedimiento real son **PENDIENTES**. No incluir telemetría de contenido, rutas o credenciales.

## Marco de referencia / alcance

Borrador basado en la propuesta U2. Para revisión jurídica se consultó la [LFPDPPP publicada por la Cámara de Diputados](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf), que indica texto vigente y última reforma publicada el 14-11-2025. Esto no demuestra cumplimiento: revisar texto y obligaciones vigentes con asesoría competente antes de uso real. Última revisión documental: 30-10-2026.

## Qué pasa si falta

Sin un aviso claro previo al registro, el usuario no puede conocer finalidades, retenciones, destinatarios ni opciones de control antes de entregar datos.
