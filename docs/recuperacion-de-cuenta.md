# Recuperación y desbloqueo de cuenta

MetaGuard permite reemplazar un autenticador TOTP perdido con la **contraseña actual y un código de recuperación sin usar**. La operación no desactiva MFA, no inicia una sesión y nunca usa el correo como único factor.

## Configurar y conservar los códigos

1. Inicia sesión y abre el alta del autenticador. La API vuelve a pedir la contraseña y entrega la semilla en una respuesta no almacenable en caché.
2. Registra la semilla en una aplicación de autenticación y confirma un código TOTP válido antes de que caduque la preparación (cinco minutos).
3. Guarda los ocho códigos de recuperación mostrados una sola vez en un lugar separado del dispositivo. La base de datos conserva solo sus digests SHA-256. La confirmación revoca las sesiones de la cuenta; inicia sesión de nuevo con un código TOTP del siguiente intervalo.

## Reemplazar un autenticador perdido

1. Envía el correo y la contraseña habitual en el login. Usa la recuperación cuando el navegador presente el desafío MFA.
2. Presenta la contraseña y un código de recuperación para obtener la nueva semilla. El TOTP, las sesiones y los códigos anteriores permanecen intactos.
3. Configura el autenticador nuevo y confirma con la contraseña, el mismo código de recuperación y el TOTP nuevo. El paso expira como máximo cuando expira el desafío que lo originó.
4. La confirmación cambia el factor y los códigos en una transacción, revoca sesiones y devuelve los códigos de reemplazo. Guarda esos códigos e inicia sesión con el autenticador nuevo. Ningún código anterior seguirá funcionando.

La preparación no autoriza un cambio: el token cifrado queda vinculado al navegador, al desafío, a la cuenta y al código de recuperación. Solo una confirmación correcta los consume. Si el guardado falla, el factor anterior, la sesión y los códigos siguen como antes. Ver el [contrato API](api.md#alta-y-recuperación-de-mfa).

## Código de correo o contraseña

Si el código de verificación no llegó o venció, abre **Cuenta → Tengo un código de verificación → Solicitar otro código**. Usa el correo y la contraseña con la que te registraste. La respuesta es genérica: no confirma la entrega de correo.

Si todavía tienes acceso, **Cuenta → Cambiar contraseña** permite cambiarla con la contraseña actual. El cambio cierra todas las sesiones; al iniciar de nuevo se conserva el MFA configurado.

### Si olvidaste tu contraseña

1. En **Iniciar sesión**, selecciona **Olvidé mi contraseña** y pide un código con el correo verificado de tu cuenta. La respuesta no confirma la existencia de la cuenta ni la entrega del mensaje. En la demo, usa una cuenta sintética y toma el código del capturador local.
2. Ingresa el código de correo, válido durante 15 minutos, y elige una contraseña nueva. Si activaste MFA, también ingresa un TOTP vigente o un código de respaldo. Si ya tienes el código de correo, puedes ir al formulario sin pedir otro.
3. Después de confirmar, inicia sesión con la contraseña nueva. Se cierran las sesiones anteriores y se invalidan sus desafíos y los otros códigos de correo pendientes. No se inicia sesión automáticamente ni se cambia el autenticador.

Si solo conservas un código de respaldo y perdiste el autenticador, ese código puede probar **un** restablecimiento de contraseña. Después usa la contraseña nueva en el inicio de sesión y, en el paso de MFA, selecciona **No tengo acceso al autenticador**. En esa ceremonia separada puedes usar el respaldo para reemplazar el autenticador una vez y recibir códigos nuevos. El correo no sustituye el segundo factor. Si no tienes acceso al correo verificado, o perdiste tanto el autenticador como todos los respaldos de una cuenta con MFA, este flujo no desbloquea la cuenta.

### Si te piden confirmar el inicio de sesión por correo

Esta prueba es distinta del registro y del restablecimiento. Se solicita después de comprobar la contraseña, ante intentos recientes desde varias direcciones y solo si la cuenta no tiene TOTP. En **Confirma el inicio de sesión**, ingresa de nuevo la contraseña y el código del correo en el mismo navegador. El código vence en cinco minutos y no funciona desde otra dirección. Si no llega, revisa el capturador local en la demo o espera a que expire antes de pedir otro. No compartas el código. Si tu cuenta tiene TOTP, MetaGuard sigue pidiendo tu autenticador, no lo sustituye por correo.

## Límites

- No hay recuperación de MFA con contraseña sola, por correo, por soporte o mediante un enlace. Tampoco se restablecen contraseñas de cuentas cuyo correo no ha sido verificado.
- No hay desactivación ni regeneración independiente de códigos. El bloqueo progresivo y los eventos de auditoría de recuperación no se incluyen en esta implementación.
- No registres contraseñas, semillas, códigos, cuerpos de recuperación ni credenciales en logs. Los límites del entorno local son por proceso y no validan la configuración de producción.
