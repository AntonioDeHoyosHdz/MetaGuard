# Datos tratados y retenidos

**Propósito:** inventariar entidades, finalidad, retención y protección conforme a la sección 3.2 de U2. **Estado:** requisitos propuestos; esquema y controles no implementados.

## Inventario de datos

| Entidad/dato | Finalidad | Retención U2 | Protección U2 | Pendiente / riesgo |
|---|---|---|---|---|
| Archivo original + copia limpia | Procesar y permitir descarga | Máximo 10 min; borrar al descargar o expirar | Memoria/temporal en memoria, AES-256-GCM, token de un uso | Método IPC y evidencia de purga. |
| Reporte | Mostrar antes/después | 24 h o borrado manual | Valores sensibles (GPS, serie, autor) cifrados por campo AES-256-GCM | Inventario de cada campo sensible. |
| Eventos de seguridad, incluida IP | Monitoreo/alertas | 30 días | Cada usuario accede solo a los propios | Campos exactos, acceso operador y purga. |
| Hash de contraseña | Autenticación | Mientras exista la cuenta | Argon2id; nunca texto claro | Parámetros Argon2id se decidirán en implementación. |
| Secreto TOTP | MFA | Mientras exista la cuenta | AES-256-GCM | Gestión de llaves y recuperación. |
| Caché de reputación | Respetar cuota de VirusTotal | 24 h | Solo hash/veredicto; sin contenido ni vínculo a usuario | Hash del original y limpio; política de consulta/consentimiento. |
| Identificador/correo de cuenta | Autenticación y alertas | No detallado en tabla U2; candidato: mientras exista cuenta | No especificado | Confirmar campos, finalidad, retención y cifrado. No guardar más por conveniencia. |

## Reglas de minimización

- Nunca almacenar contraseña en claro, contenido de archivo en logs ni hash SHA-1 completo para la verificación de brechas.
- Borrado de cuenta debe eliminar reportes y eventos asociados, según U2 §3.3; el detalle de retención residual por respaldos está pendiente.
- Métricas/telemetría deben ser agregadas y no incluir rutas, GPS, nombres de archivo ni hashes completos sin necesidad aprobada.
- No declarar cumplida una retención hasta probar purga y acceso por objeto.

## Qué pasa si falta

Sin inventario no se pueden justificar finalidades, plazos, accesos ni cifrado, y se corre el riesgo de conservar datos personales fuera del alcance anunciado.
