# Enviar códigos de verificación sin dominio propio

MetaGuard puede usar una cuenta Gmail dedicada como remitente de pruebas. El adaptador no modifica la demo local, no crea cuentas de Google y no envía nada hasta que el despliegue lo conecte explícitamente. No debe confundirse con «Iniciar sesión con Google»: los destinatarios pueden usar Gmail u otro proveedor.

## Preparar el remitente

1. Desde una cuenta Gmail **dedicada a este entorno**, activa la verificación en dos pasos y crea una [contraseña de aplicación](https://support.google.com/accounts/answer/185833?hl=es), si la cuenta ofrece esa opción. No uses la contraseña habitual. Google no ofrece contraseñas de aplicación en algunas cuentas de organización o con políticas de protección específicas.
2. Monta esa credencial como el archivo `gmail_app_password`, de solo lectura para el backend, dentro de `METAGUARD_SECRET_DIR` (por defecto `/run/secrets`). Usa el valor de 16 caracteres sin los espacios de presentación. No lo pongas en Git, argumentos de proceso, variables públicas del frontend ni registros.
3. Permite la salida **del backend** hacia `smtp.gmail.com:465` por TLS. No des acceso a la credencial al frontend, a PostgreSQL ni al procesador de archivos.

## Conectar el adaptador en staging

La composición autorizada del despliegue debe construir el `AuthRuntime` completo (PostgreSQL, sesiones, llaves y límites) como hasta ahora y sustituir solo su dependencia de correo:

```python
from dataclasses import replace

from metaguard_api.gmail_sender import GmailSender
from metaguard_api.main import create_app
from metaguard_api.secrets import SecretStore

sender = GmailSender(
    sender_email="cuenta.staging@gmail.com",
    secret_store=SecretStore(settings.secret_dir),
)
app = create_app(
    settings,
    auth_runtime=replace(auth_runtime, email_sender=sender),
    file_runtime=file_runtime,
    database=database,
)
```

Este fragmento va en la composición del despliegue: `settings`, `auth_runtime`, `file_runtime` y `database` son dependencias que ese entorno ya construye. No es un comando para arrancar el demo. El punto de entrada predeterminado no configura el envío. La cuenta usada para autenticar el SMTP es también el remitente; la dirección de registro aparece solo como destinataria, no en el cuerpo del mensaje.

## Qué recibe la persona

El correo llega con el asunto «MetaGuard | Verifica tu correo» y dos versiones en español: HTML con la identidad visual de MetaGuard y texto plano. Ambas muestran el mismo código completo y indican elegir **Tengo un código de verificación** en **Cuenta** y luego pulsar **Verificar correo**. El mensaje no incluye enlaces, imágenes remotas ni rastreadores.

## Verificar y volver atrás

- Primero ejecuta las pruebas con SMTP simulado; no necesitan credenciales ni internet. Antes de un envío real, autoriza el entorno, el remitente y el buzón de prueba.
- En un entorno privado, verifica que un correo de prueba llega, que el código solo se acepta una vez y que la credencial, el código y la dirección no aparecen en registros ni respuestas HTTP.
- Un SMTP que acepta el mensaje no garantiza entrega. Si el servicio rechaza el envío, el registro falla con un mensaje genérico y no completa la transacción de cuenta y código. Si la base de datos falla **después** de que SMTP aceptó el mensaje, ese correo no se puede recuperar; este cambio no añade una cola transaccional.
- Revoca la contraseña de aplicación y vuelve al capturador local para retirar el acceso. Gmail tiene [límites de envío](https://support.google.com/mail/answer/22839); no se considera un servicio de correo transaccional validado para el registro público. No abras el alta a usuarios reales hasta completar la [validación de staging](validacion-staging.md) y revisar el [aviso de privacidad](aviso-de-privacidad.md).

Referencias de implementación: [perfil SMTP de Gmail en Nodemailer](https://github.com/nodemailer/nodemailer/blob/master/src/well-known/services.json) y [`smtplib` en CPython](https://github.com/python/cpython/blob/main/Doc/library/smtplib.rst).
