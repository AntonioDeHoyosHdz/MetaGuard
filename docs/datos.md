# Datos tratados y retenidos

**Propósito:** inventariar entidades, finalidad, retención y protección conforme a la sección 3.2 de U2. **Estado:** requisitos propuestos; solo existe una implementación parcial de la caché de reputación, sin conexión al proveedor ni purga programada.

## Inventario de datos

| Entidad/dato | Finalidad | Retención U2 | Protección U2 | Pendiente / riesgo |
|---|---|---|---|---|
| Archivo original + copia limpia | Procesar y permitir descarga | Máximo 10 min; borrar al descargar o expirar | Memoria/temporal en memoria, AES-256-GCM, token de un uso | Método IPC y evidencia de purga. |
| Reporte | Mostrar antes/después | 24 h o borrado manual | Valores sensibles (GPS, serie, autor) cifrados por campo AES-256-GCM | Inventario de cada campo sensible. |
| Eventos de seguridad, incluida IP | Monitoreo/alertas | 30 días | Cada usuario accede solo a los propios | Campos exactos, acceso operador y purga. |
| Hash de contraseña | Autenticación | Mientras exista la cuenta | Argon2id; nunca texto claro | Parámetros Argon2id se decidirán en implementación. |
| Secreto TOTP | MFA | Mientras exista la cuenta | AES-256-GCM | Gestión de llaves y recuperación. |
| Caché de reputación | Respetar cuota de VirusTotal | 24 h | Solo hash/veredicto; sin contenido ni vínculo a usuario | Implementación interna parcial: entradas vencidas no se devuelven, pero la eliminación requiere programar la purga. Consulta y consentimiento pendientes. |
| Correo de cuenta | Identificador de inicio de sesión y recuperación, según confirmación del usuario | Propuesto: mientras exista la cuenta; borrado pendiente | La primera migración lo almacena en texto plano y exige minúsculas y unicidad; protección de acceso y cifrado en reposo pendientes | Registro, verificación de correo, recuperación, política de normalización y retención verificable pendientes. |

## Reglas de minimización

- Nunca almacenar contraseña en claro, contenido de archivo en logs ni hash SHA-1 completo para la verificación de brechas.
- Borrado de cuenta debe eliminar reportes y eventos asociados, según U2 §3.3; el detalle de retención residual por respaldos está pendiente.
- Métricas/telemetría deben ser agregadas y no incluir rutas, GPS, nombres de archivo ni hashes completos sin necesidad aprobada.
- No declarar cumplida una retención hasta probar purga y acceso por objeto.

## Qué pasa si falta

Sin inventario no se pueden justificar finalidades, plazos, accesos ni cifrado, y se corre el riesgo de conservar datos personales fuera del alcance anunciado.

La tabla inicial de cuentas es solo persistencia: todavía no existe un flujo de registro ni de recuperación. La normalización completa del correo, incluidos casos internacionales y direcciones con parte local sensible a mayúsculas, necesita definirse antes de habilitar esos flujos; no asumir que convertir a minúsculas funciona para todos los proveedores.

La reversión de la migración 0002_accounts elimina la tabla y sus cuentas: requiere respaldo y autorización antes de ejecutarse con datos reales. La restricción SQL de minúsculas no garantiza normalización Unicode consistente entre bases de datos.