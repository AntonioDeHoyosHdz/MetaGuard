# Recuperación y desbloqueo de cuenta

**Propósito:** recuperar acceso sin convertir soporte o correo en bypass de MFA. **Estado:** flujo candidato; plazos, intentos y contacto oficial pendientes.

## Flujo propuesto

1. Usuario autenticado guarda códigos de respaldo de un solo uso; almacenar solo hashes de esos códigos y permitir regenerarlos tras reautenticación.
2. Pérdida de TOTP: verificar la contraseña actual y un código de respaldo. Si no existe respaldo, el usuario aún debe demostrar la contraseña actual y completar un enlace aleatorio enviado a su correo verificado; el enlace es de un solo uso y tiene expiración corta (**TTL pendiente**).
3. Aplicar periodo de espera (**duración pendiente**) antes de quitar MFA; notificar a correo anterior/nuevo y permitir cancelar mientras la solicitud está pendiente.
4. Tras la espera y verificación, revocar sesiones y códigos viejos, permitir registrar TOTP nuevo y emitir nuevos códigos. No revelar si una cuenta/correo existe.
5. Desbloqueo por fuerza bruta: tras 5 fallos del mismo par cuenta+IP, bloqueo progresivo 1/5/15 min según prompt. No bloquear la cuenta por fallos distribuidos desde muchas IP; exigir desafío TOTP/correo y alertar.

Si el usuario perdió simultáneamente contraseña, TOTP y códigos de respaldo, el correo por sí solo no basta para desactivar MFA; un método de evidencia de identidad alternativo y cualquier eventual excepción de seguridad quedan pendientes de aprobación. No se ofrece recuperación que reduzca MFA solo por poseer el buzón.

## Controles y preguntas

- Endpoint de recuperación no existe aún; tasa, cooldown, vencimiento de enlaces y método para validar cambios son **PENDIENTES**.
- Los administradores no pueden cambiar contraseñas ni desactivar MFA sin evidencia del flujo y auditoría; soporte nunca solicita contraseña/código.
- Registrar solicitud, éxito, cancelación y desbloqueo sin guardar enlaces, códigos ni valores de autenticación.

## Qué pasa si falta

Sin recuperación segura, el usuario puede quedar fuera o un atacante puede usar el soporte/correo como ruta para tomar la cuenta y eludir TOTP.
