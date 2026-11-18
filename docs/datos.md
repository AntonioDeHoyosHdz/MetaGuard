# Datos tratados y retenidos

**Propósito:** inventariar entidades, finalidad, retención y protección conforme a la sección 3.2 de U2. **Estado:** hay rutas T3d2/T3d3 de carga, análisis, reporte y descarga detrás de dependencias inyectadas, además de una primitiva privada de archivo temporal cifrado en memoria. No hay runtime/llave productiva configurados ni se demostró retención/purga del producto; el flujo no es multi-worker durable.

## Inventario de datos

| Entidad/dato | Finalidad | Retención U2 | Protección U2 | Pendiente / riesgo |
|---|---|---|---|---|
| Archivo original + copia limpia | Procesar y permitir descarga | Original y copia limpia dejan de ser legibles tras 10 min según reloj UTC del llamador; copia limpia también se borra al descargar o al borrar explícitamente el reporte | `InMemoryTemporaryFileStore` cifra AES-256-GCM en memoria con llave de 32 bytes inyectada, AAD ligado a file/owner IDs y límite de bytes. No se escribe archivo en disco por esta primitiva. | T3d2/T3d3 rutas sintéticas existen, pero no hay runtime ni clave productiva. La expiración niega lectura y elimina en lectura/purga; no hay limpieza programada del store y el CLI de mantenimiento separado no puede borrarlo. No hay durabilidad entre procesos, retención multi-worker ni garantía de borrado físico de memoria. |
| Reporte | Mostrar el resultado minimizado y permitir descargar la copia limpia | Fila DB: 24 h y borrado manual; token: máximo 10 min y no después del vencimiento de la copia limpia; copia limpia: 10 min desde análisis | `file_reports` conserva dueño, ID, timestamps y JSON con solo la proyección allowlisted `ProcessingReport`: MIME, categorías de nombres, verificación, dimensiones/páginas y contadores/flags. No guarda valores de GPS, serie, autor u otros metadatos extraídos. El token se persiste solo como digest SHA-256 y se consume una vez. | Pruebas con SQLite/mocks, sin prueba de concurrencia PostgreSQL ni DB/ruta de despliegue real. El maintenance command purga filas DB solo al ejecutarse; no está programado. No afirmar cifrado de campo ni protección de DB en reposo más allá del entorno no verificado. |
| Eventos de seguridad, incluida IP | Monitoreo/alertas | 30 días | Cada usuario accede solo a los propios | Campos exactos, acceso operador y purga. |
| Hash de contraseña | Autenticación | Mientras exista la cuenta | Argon2id; nunca texto claro | Parámetros Argon2id se decidirán en implementación. |
| Secreto TOTP | MFA | Mientras exista la cuenta | AES-256-GCM | Gestión de llaves y recuperación. |
| Caché de reputación | Respetar cuota de VirusTotal | 24 h | Solo hash/veredicto; sin contenido ni vínculo a usuario | Implementación interna parcial: entradas vencidas no se devuelven, pero la eliminación requiere programar la purga. Consulta y consentimiento pendientes. |
| Correo de cuenta | Identificador de inicio de sesión y recuperación, según confirmación del usuario | Propuesto: mientras exista la cuenta; borrado pendiente | La primera migración lo almacena en texto plano y exige minúsculas y unicidad; protección de acceso y cifrado en reposo pendientes | Registro, verificación de correo, recuperación, política de normalización y retención verificable pendientes. |

## Reglas de minimización

- Nunca almacenar contraseña en claro, contenido de archivo en logs ni hash SHA-1 completo para la verificación de brechas.
- Borrado de cuenta debe eliminar reportes y eventos asociados, según U2 §3.3; el detalle de retención residual por respaldos está pendiente.
- Métricas/telemetría deben ser agregadas y no incluir rutas, GPS, nombres de archivo ni hashes completos sin necesidad aprobada.
- No declarar cumplida una retención hasta probar purga y acceso por objeto. La prueba sintética no equivale a evidencia de un runtime real ni de PostgreSQL concurrente.

## Qué pasa si falta

Sin inventario no se pueden justificar finalidades, plazos, accesos ni cifrado, y se corre el riesgo de conservar datos personales fuera del alcance anunciado.

La tabla inicial de cuentas es solo persistencia: todavía no existe un flujo de registro ni de recuperación. La normalización completa del correo, incluidos casos internacionales y direcciones con parte local sensible a mayúsculas, necesita definirse antes de habilitar esos flujos; no asumir que convertir a minúsculas funciona para todos los proveedores.

La reversión de la migración 0002_accounts elimina la tabla y sus cuentas: requiere respaldo y autorización antes de ejecutarse con datos reales. La restricción SQL de minúsculas no garantiza normalización Unicode consistente entre bases de datos.
