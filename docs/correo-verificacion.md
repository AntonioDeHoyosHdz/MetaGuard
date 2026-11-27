# Enviar códigos de verificación sin dominio propio

MetaGuard puede usar una cuenta Gmail dedicada como remitente de pruebas. El adaptador no modifica la demo local, no crea cuentas de Google y no envía nada hasta que el despliegue lo conecte explícitamente. No debe confundirse con «Iniciar sesión con Google»: los destinatarios pueden usar Gmail u otro proveedor.

## Preparar el remitente

1. Desde una cuenta Gmail **dedicada a este entorno**, activa la verificación en dos pasos y crea una [contraseña de aplicación](https://support.google.com/accounts/answer/185833?hl=es), si la cuenta ofrece esa opción. No uses la contraseña habitual. Google no ofrece contraseñas de aplicación en algunas cuentas de organización o con políticas de protección específicas.
2. Monta esa credencial como el archivo `gmail_app_password`, de solo lectura para el backend, dentro de `METAGUARD_SECRET_DIR` (por defecto `/run/secrets`). Usa el valor de 16 caracteres sin los espacios de presentación. No lo pongas en Git, argumentos de proceso, variables públicas del frontend ni registros.
3. Permite la salida **del backend** hacia `smtp.gmail.com:465` por TLS. No des acceso a la credencial al frontend, a PostgreSQL ni al procesador de archivos.

## Ensayo de registro aislado

El staging existente sigue siendo sintético y no tiene envío real. La fábrica `metaguard_api.registration_trial:create_registration_trial_app` prepara un ensayo distinto, desactivado por defecto, con solo el estado de sesión, registro, verificación, reenvío, inicio y cierre de sesión. No activa alertas, restablecimiento, desafíos por correo, análisis de archivos ni consultas externas de contraseñas o reputación.

| Límite | Requisito del ensayo |
| --- | --- |
| Arranque | Usuario de Linux sin privilegios, `METAGUARD_REGISTRATION_PRIVATE_TRIAL=true` y `METAGUARD_ENVIRONMENT=production`, con un solo origen HTTPS exacto en `METAGUARD_AUTH_ALLOWED_ORIGINS`. |
| PostgreSQL | IP privada, base dedicada y migrada `metaguard_registration_trial`, rol no administrador `metaguard_registration_app`, CA en ruta absoluta `METAGUARD_REGISTRATION_DB_TLS_CA`. No reutilizar la base, el rol ni las llaves de staging. |
| Llaves | Directorios de secretos del servicio y de PostgreSQL con las credenciales correspondientes. Montar solo el archivo `gmail_app_password` para el correo con `LoadCredential`; systemd expone el directorio al servicio como `CREDENTIALS_DIRECTORY`. Configurar la dirección del remitente con `METAGUARD_REGISTRATION_GMAIL_SENDER`. |
| Contraseñas | Lista local no vacía en una ruta absoluta mediante `METAGUARD_REGISTRATION_PASSWORD_BLOCKLIST`. El ensayo registra un evento genérico de comprobación reducida; no consulta HIBP. |

Con esos límites satisfechos, el comando del **ensayo privado** es:

```bash
uv run --offline --no-sync uvicorn metaguard_api.registration_trial:create_registration_trial_app \
  --factory --host 127.0.0.1 --port 8010 --workers 1 --no-proxy-headers --no-access-log
```

Registro y reenvío comparten una cuota conservadora de **3 intentos por destinatario por hora, 12 por servicio por hora y 48 por servicio por 24 horas**. Son intentos admitidos, no mensajes enviados. La cuota es local al proceso y no persiste tras reiniciarlo. No añadirá IP de visitantes al registro del backend ni reemplaza límites en el proxy.

No añadas este ensayo al Nginx público ni le abras un puerto en AWS. Antes de un despliegue público, hacen falta límites probados por visitante y una cuota operativa que no pueda restablecerse con un reinicio de la API, un aviso aprobado y una prueba de entrega y canje real. Para retirar el ensayo, detén el servicio aislado y quita su montaje de la credencial; no hay que cambiar el staging.

### Entrada privada para probar desde el sitio desplegado

Para un ensayo desde un solo origen de red autorizado, la fábrica `create_registration_ingress_app` conserva las seis operaciones de cuenta. Requiere además `METAGUARD_REGISTRATION_INGRESS_ENABLED=true` y `METAGUARD_REGISTRATION_INGRESS_PEER` con la IPv4 privada exacta del frontend. El backend exige HTTPS y el `Host` configurado, rechaza cabeceras de reenvío y no acepta servicios distintos del frontend. Conserva `--no-proxy-headers` y `--no-access-log`.

Los fragmentos `deploy/public/registration-preview-http.nginx.conf` y `deploy/public/registration-preview-server.nginx.conf` se instalan solamente en una copia de revisión antes de evaluar su publicación. El segundo exige una IP de prueba `/32`, verificación de la CA y el nombre TLS `metaguard-registration.internal` para el backend. El grupo de seguridad del backend debe admitir TCP 8011 **solo** desde el frontend. No abras ese puerto a Internet ni reemplaces el listener de staging.

Los instaladores en `deploy/registration-preview/` dejan el backend de prueba sin arranque automático y reutilizan la IP autorizada del ensayo anterior. Conservan el HTML público original y sirven una copia con aviso únicamente al operador. Prueba en una ventana privada: las sesiones de esta base no son válidas en el ensayo de archivos del mismo dominio. Si hay que retirar la prueba, restaura el `nginx.conf` del respaldo de la activación, valida con `nginx -t -c /etc/metaguard-public/nginx.conf`, recarga y detén `metaguard-registration-preview.service`. No borres ni reutilices la base, los secretos o el certificado de la prueba sin revisar la política de conservación.

## Qué recibe la persona

El correo llega con el asunto «MetaGuard | Verifica tu correo» y dos versiones en español: HTML con la identidad visual de MetaGuard y texto plano. Ambas muestran el mismo código completo y indican elegir **Tengo un código de verificación** en **Cuenta** y luego pulsar **Verificar correo**. El mensaje no incluye enlaces, imágenes remotas ni rastreadores.

## Verificar y volver atrás

- Primero ejecuta las pruebas con SMTP simulado; no necesitan credenciales ni internet. Antes de un envío real, autoriza el entorno, el remitente y el buzón de prueba.
- En un entorno privado, verifica que un correo de prueba llega, que el código solo se acepta una vez y que la credencial, el código y la dirección no aparecen en registros ni respuestas HTTP.
- En el ensayo aislado, el servicio confirma la cuenta y la huella del código en la base antes de intentar el envío. La aceptación de la solicitud (HTTP `202`) no significa que se haya entregado el correo. Si Gmail rechaza la entrega o el proceso se interrumpe antes del envío, la cuenta pendiente puede solicitar otro código con la misma contraseña. No hay una cola persistente ni reintentos automáticos. Los demás modos conservan el comportamiento anterior.
- Revoca la contraseña de aplicación y vuelve al capturador local para retirar el acceso. Gmail tiene [límites de envío](https://support.google.com/mail/answer/22839); no se considera un servicio de correo transaccional validado para el registro público. No abras el alta a usuarios reales hasta completar la [validación de staging](validacion-staging.md) y revisar el [aviso de privacidad](aviso-de-privacidad.md).

Referencias de implementación: [perfil SMTP de Gmail en Nodemailer](https://github.com/nodemailer/nodemailer/blob/master/src/well-known/services.json) y [`smtplib` en CPython](https://github.com/python/cpython/blob/main/Doc/library/smtplib.rst).
