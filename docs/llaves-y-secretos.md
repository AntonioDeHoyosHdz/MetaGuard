# Gestión de llaves y secretos — demo aprobada; producción pendiente

**Propósito:** limitar acceso a llaves de cifrado y credenciales externas. **Estado:** el usuario eligió Docker Secrets montados al runtime como fuente para la demo el 30 de octubre de 2026. KMS, responsables y rotación periódica de producción siguen pendientes. La aprobación no define el canal API–worker ni autoriza compartir secretos con el worker.

El entorno del backend incluye bibliotecas fijadas para Argon2id, AES-GCM, JWT y TOTP, con pruebas básicas de sus primitivas. Esto **no implementa todavía** cuentas, MFA, cifrado de campos, gestión de sesiones ni recuperación; sus parámetros y flujos deben verificarse al integrarlos.

## Inventario y acceso propuesto

| Secreto | Quién lo necesita | Dónde viviría | Regla |
|---|---|---|---|
| Llave de cifrado de datos (DEK) | API para reportes; uso efímero del worker todavía no diseñado | Docker Secret montado al runtime de demo; nunca repositorio ni imagen | Separar propósitos; AES-256-GCM, nonce único por llave; identificar versión sin guardar llave. No entregarla al worker hasta definir y revisar IPC. |
| Llave de envoltura (KEK) | API o servicio de llaves para envolver/desenvolver DEK | Docker Secret para demo; KMS para producción pendiente | No pasarla al worker ni a la base de datos. |
| JWT signing key | API autenticadora | Docker Secret montado al runtime de demo | Separada de llaves de cifrado; permisos mínimos. |
| Credencial HIBP/VT/SMTP | Solo conector API que la necesita | Docker Secret si el conector se habilita | No imprimir en logs; VT no recibe archivo, solo hash bajo consentimiento. |
| Secreto TOTP cifrado | API | DB como ciphertext; llave fuera de DB | Descifrar solo para validar TOTP. |

Cuando se implemente, la API almacenará ciphertext, nonce, tag e identificador de versión; el campo de clave nunca se guardará junto con el ciphertext. La memoria/IPC que entregue una llave temporal al worker debe evitar argumentos de proceso, logs y disco; canal exacto **PENDIENTE**. Operador, responsable de aprobación y proveedor para producción **PENDIENTES**.

En demo, los secretos se montan como archivos de solo lectura en `/run/secrets` y solo al servicio que los necesita. La aplicación debe fallar cerrada si falta una llave requerida; no usar valores de respaldo de desarrollo en despliegue. Las rutas concretas y los nombres de los archivos se documentarán con la configuración que los consuma.

## Rotación y filtración

- Periodicidad y esquema de versiones para producción: **PENDIENTES de aprobación**. Rotar de inmediato ante sospecha/confirmación de filtración, cambio de privilegios o exposición accidental. El mecanismo operativo de rotación de Docker Secrets para demo se debe probar antes de uso.
- Aislar el secreto comprometido, revocar credenciales relacionadas, preservar evidencia sin registrar la llave, rotar, re-cifrar datos retenidos cuando aplique y verificar acceso mínimo.
- Las llaves antiguas se conservan solo lo necesario para descifrar datos que sigan dentro de retención; archivos temporales se purgan al terminar/expirar.
- Secretos `.env`, tokens, llaves y dumps no se suben a GitHub; `.gitignore` excluye `.env*` como barrera adicional, no como gestor de secretos.

## Qué pasa si falta

Sin inventario/rotación, un ciphertext exfiltrado puede volverse legible y una llave filtrada seguir válida sin fecha de revocación ni responsables.

## Protección de contraseñas: componente interno

`account_credentials` genera hashes Argon2id con sal aleatoria de 16 bytes y parámetros fijos (19 MiB, 2 iteraciones, paralelismo 1). Solo verifica el formato y los parámetros emitidos por esta versión; antes de cambiarlos hará falta una estrategia de migración y rehash. El límite de entrada de 1024 bytes UTF-8 protege recursos y no reemplaza una política de contraseñas. Se rechazan hashes malformados antes de llamar a Argon2.

Este componente no implementa cuentas, inicio de sesión, MFA, controles de tasa ni recuperación; no debe exponerse como autenticación completa.

## Cifrado interno de secretos TOTP

El componente interno `totp_secrets` usa AES-256-GCM, una clave de 32 bytes suministrada por el llamador y un nonce aleatorio nuevo de 12 bytes por cifrado. Autentica el identificador de cuenta como dato asociado y rechaza alteraciones o claves equivocadas. El formato tiene una versión, pero todavía no incorpora identificador de clave ni rotación. No crea cuentas, almacena secretos, configura MFA ni lee automáticamente Docker Secrets; esas integraciones y el ciclo de vida de claves siguen pendientes.

Al integrar este componente, el dato asociado debe ser el identificador de cuenta inmutable y canónico, no el correo, que puede cambiar.

La migración `0003_account_totp` agrega almacenamiento asociado a la cuenta con versión de clave y último paso aceptado. La base solo valida la longitud del campo: no demuestra que el contenido esté cifrado. El futuro flujo de inscripción debe usar cifrado autenticado. La validación atómica interna se describe abajo, pero aún no está conectada al inicio de sesión. Revertir la migración elimina los secretos TOTP almacenados y requiere respaldo y autorización antes de tocar datos reales.

El componente interno `consume_totp` valida el código del paso actual de 30 segundos y actualiza condicionalmente el último paso aceptado en la transacción del llamador. No concede acceso: el llamador debe confirmar la transacción antes de autenticar y suministrar tiempo confiable. No hay ventana de deriva, límites de intentos, inscripción, inicio de sesión ni política de recuperación implementados. La concurrencia y el comportamiento de PostgreSQL real aún necesitan validación en ese motor.
