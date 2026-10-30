# Gestión de llaves y secretos — demo aprobada; producción pendiente

**Propósito:** limitar acceso a llaves de cifrado y credenciales externas. **Estado:** el usuario eligió Docker Secrets montados al runtime como fuente para la demo el 30 de octubre de 2026. KMS, responsables y rotación periódica de producción siguen pendientes. La aprobación no define el canal API–worker ni autoriza compartir secretos con el worker.

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
