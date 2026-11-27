# Gestión de llaves y secretos

Genera llaves exclusivas para [desarrollo local](desarrollo-local.md), fuera del repositorio y con acceso restringido. El diseño de demo en contenedores seleccionó archivos montados de solo lectura; el runtime local permite un directorio protegido indicado por el operador. No hay gestor de llaves, rotación periódica ni responsables aprobados para producción.

## Qué necesita cada componente

| Archivo | Uso | Regla |
|---|---|---|
| `postgres_password` | Conexión de la API y migraciones contra una base descartable | Su directorio se configura por separado mediante `METAGUARD_DB_SECRET_DIR`. |
| `jwt_signing_key` | Firmar sesiones de la API | Texto aleatorio de al menos 32 bytes UTF-8, independiente de las llaves de cifrado. |
| `totp_encryption_key` | Cifrar semillas TOTP | 32 bytes binarios exclusivos. El material no se almacena en PostgreSQL. |
| `data_encryption_key` | Cifrar originales y copias limpias en la memoria del API | 32 bytes binarios distintos de la llave TOTP. Solo si hay runtime de archivos. No se entrega al procesador. |
| Certificado y llave TLS local | Servir la demo HTTPS desde Vite | Archivos PEM fuera del repositorio. Solo Vite recibe la llave; usa un certificado de confianza con SAN para la IP de loopback. |
| `virustotal_api_key` | Consultas de reputación optativas | Solo para el conector en la API y con autorización independiente. No se necesita en la demo. |
| `gmail_app_password` | Adaptador Gmail optativo | Solo para el remitente de prueba autorizado en la API y si se inyecta el adaptador. La demo no lo usa. Ver [correo de verificación](correo-verificacion.md). |

La API toma la ruta de su directorio mediante `METAGUARD_SECRET_DIR`; la variable nunca contiene las llaves. El procesador no necesita secretos JWT, TOTP, de cifrado temporal ni de proveedores. La contraseña de cuenta se verifica con Argon2id (sal aleatoria de 16 bytes, 19 MiB, dos iteraciones y paralelismo uno). El formato actual fija esos parámetros; cualquier cambio requiere una estrategia de rehash. La semilla TOTP usa AES-256-GCM con nonce aleatorio y el identificador inmutable de cuenta como dato asociado. Las rutas de alta y recuperación se describen en el [contrato de la API](api.md#alta-y-recuperación-de-mfa).

## VirusTotal fuera de la demo

El proveedor permanece desactivado en el runtime local de presentación. Una prueba separada exige autorización, plan compatible con el uso, procesador aislado y archivos sintéticos con consentimiento explícito por archivo. El conector lee `virustotal_api_key` mediante `SecretStore`; si falta o se rechaza la llave (401/403), no envía archivos ni expone la credencial. El análisis continúa sin resultado de reputación. Las pruebas automáticas no necesitan red ni una llave real.

## Rotación y filtración

- No subas llaves, tokens, archivos `.env` ni respaldos al repositorio; tampoco los pases en argumentos, logs, capturas, variables del cliente web o imágenes.
- Ante una posible filtración, aísla y revoca la credencial, conserva evidencia sin secretos, rota y comprueba el acceso mínimo. Si hay datos que deban conservarse, planifica primero su recifrado o migración.
- En producción siguen pendientes el esquema de rotación y versiones, la custodia de llaves, un KMS/KEK si se adopta y el ensayo de recuperación. No reutilices las llaves de desarrollo.
