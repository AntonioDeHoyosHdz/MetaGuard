# Gestión de llaves y secretos — diseño pendiente

**Propósito:** limitar acceso a llaves de cifrado y credenciales externas. **Estado:** los controles aquí son candidatos; proveedor, responsables y rotación periódica requieren decisión.

## Inventario y acceso propuesto

| Secreto | Quién lo necesita | Dónde viviría | Regla |
|---|---|---|---|
| Llave de cifrado de datos (DEK) | API para reportes; uso efímero del worker para procesar el archivo | Fuente de secretos/llavero del despliegue; nunca repositorio ni imagen | Separar por propósito; AES-256-GCM, nonce único por llave; identificar versión sin guardar llave. |
| Llave de envoltura (KEK) | API o servicio de llaves para envolver/desenvolver DEK | KMS o Docker Secret protegido en demo; elección PENDIENTE | No pasarla al worker ni a la base de datos. |
| JWT signing key | API autenticadora | Fuente de secretos del runtime | Separada de llaves de cifrado; permisos mínimos. |
| Credencial HIBP/VT/SMTP | Solo conector API que la necesita | Secretos del runtime | No imprimir en logs; VT no recibe archivo, solo hash bajo consentimiento. |
| Secreto TOTP cifrado | API | DB como ciphertext; llave fuera de DB | Descifrar solo para validar TOTP. |

API almacena ciphertext, nonce, tag e identificador de versión; el campo de clave nunca se guarda junto con el ciphertext. La memoria/IPC que entregue una llave temporal al worker debe evitar argumentos de proceso, logs y disco; canal exacto **PENDIENTE**. Operador, responsable de aprobación y proveedor para producción **PENDIENTES**.

## Rotación y filtración

- Periodicidad y esquema de versiones: **PENDIENTES de aprobación**. Rotar de inmediato ante sospecha/confirmación de filtración, cambio de privilegios o exposición accidental.
- Aislar el secreto comprometido, revocar credenciales relacionadas, preservar evidencia sin registrar la llave, rotar, re-cifrar datos retenidos cuando aplique y verificar acceso mínimo.
- Las llaves antiguas se conservan solo lo necesario para descifrar datos que sigan dentro de retención; archivos temporales se purgan al terminar/expirar.
- Secretos `.env`, tokens, llaves y dumps no se suben a GitHub; `.gitignore` excluye `.env*` como barrera adicional, no como gestor de secretos.

## Qué pasa si falta

Sin inventario/rotación, un ciphertext exfiltrado puede volverse legible y una llave filtrada seguir válida sin fecha de revocación ni responsables.
