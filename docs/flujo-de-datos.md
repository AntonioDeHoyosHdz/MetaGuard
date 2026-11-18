# Flujo de datos de MetaGuard

**Propósito:** definir el recorrido, cifrado y borrado de una carga, conforme a OBJ-01 y al ciclo de datos U2. **Estado:** están implementadas la primitiva privada `InMemoryTemporaryFileStore` y las rutas T3d2/T3d3 para dependencias inyectadas y pruebas sintéticas. No hay runtime productivo, clave productiva, proveedor VirusTotal ni evidencia de ejecución real del sandbox. El store cifra en memoria con AES-256-GCM, liga contenido a IDs/propietario, aplica un límite de bytes y vencimiento de 10 minutos según la hora UTC del llamador; no escribe archivos ni promete durabilidad entre procesos o borrado físico de memoria. La retención/purga solo tiene pruebas sintéticas; no se afirma programación de mantenimiento ni preparación multi-worker.

## Los cinco pasos

| Paso | Recorrido y control | Dato / retención |
|---|---|---|
| 1. Recibir | Navegador → Nginx por TLS. Nginx limita cuerpo y tasa, descarta cabeceras de IP del cliente y establece la IP según la topología confiable. | Solicitud y archivo no confiables. |
| 2. Aceptar | La API valida sesión vigente, Origin/CSRF exactos y límites inyectados; recibe bytes crudos con `Content-Type` allowlist y comprueba el límite configurado mientras consume el stream. No decodifica multipart ni analiza bytes de archivo. Guarda el original mediante `InMemoryTemporaryFileStore` y un runtime inyectado. | Cifrado AES-256-GCM en memoria, ligado a propietario/ID; vencimiento de 10 min según reloj UTC inyectado. La aplicación por defecto no inyecta store ni llave y devuelve `503`. No se calcula SHA-256 en esta ruta. |
| 3. Procesar | La ruta verifica el dueño y llama solo al `ProcessingClient` API-side inyectado; FastAPI no invoca Docker ni parser. El contrato privado del supervisor/worker sigue siendo la frontera prevista. | Solo el runtime externo configurado podría ejecutar IPC/sandbox; no hay prueba de runtime Docker, aislamiento, red o límites en esta tarea. No se afirma que el contenido claro nunca toque disco fuera de esa prueba. |
| 4. Reportar | T3d2 valida la proyección allowlisted del `ProcessingReport`; T3d3 guarda el archivo limpio en el store cifrado del proceso y persiste únicamente esa proyección, propietario, ID y tiempos de retención en `file_reports`. `virus_total_consent` tiene default `false`, pero no existe proveedor conectado aquí. | El reporte DB vence a las 24 h y se oculta desde su vencimiento. No se guardan valores de metadatos extraídos ni los bytes de archivo en la tabla. No hay consulta VirusTotal ni claim de seguridad/ausencia. |
| 5. Descargar/purgar | Las rutas owner-only emiten un token opaco una sola vez al dueño; se persiste únicamente SHA-256 y el consumo usa una actualización SQL atómica. La ruta descarga bytes de la copia limpia y borra esa copia al consumir el token; el borrado manual de reporte también intenta borrarla. | Token: máximo 10 min desde emisión y no más allá de la ventana de la copia. La copia cifrada deja de estar disponible a los 10 min del análisis; el store no tiene trabajo programado de limpieza. El comando existente purga filas DB expiradas junto con otros datos, solo cuando se ejecuta. |

## Flujos laterales y reglas

- HIBP se limita a verificación de contraseña en registro/cambio: solo prefijo de 5 caracteres SHA-1 con padding; comparación local. No forma parte del procesamiento de archivos.
- Reportes guardan solo categorías y métricas de la proyección minimizada allowlisted; no cifran ni persisten valores de metadatos extraídos. Los tokens de descarga se guardan como digest. Eventos de seguridad se conservan 30 días y cada usuario solo consulta los propios.
- No registrar cuerpo, contenido extraído, contraseña, hash completo de contraseña, token de sesión/descarga ni llaves. Minimizar también nombre original y errores de parser.
- El borrado DB al expirar requiere ejecutar `purge-maintenance`; esa acción no está programada por este cambio. Un CLI en otro proceso no puede purgar `InMemoryTemporaryFileStore`; el archivo limpio deja de ser legible por TTL, pero el ciphertext puede persistir en la memoria del proceso hasta una lectura/purga/eliminación posterior. No se afirma borrado físico de memoria ni retención multi-worker.

## Qué pasa si falta

Sin este mapa se pierden de vista copias temporales, terceros, claves y plazos; no se puede demostrar minimización ni purga.

## Verificación

La primitiva privada tiene pruebas sintéticas de cifrado, ownership, límites, reloj y purga. T3d2/T3d3 agregan pruebas de rutas con almacenamiento/procesador simulados: carga binaria, límite, Origin/CSRF, sesión, rate limiter, propiedad, proyección minimizada, digest/consumo único, vencimiento y borrado manual/por descarga; migración y purga DB usan SQLite. Estas pruebas no demuestran concurrencia en PostgreSQL ni retención/runtime del producto. Siguen pendientes: ejecución real de Docker, límites y aislamiento de la imagen, integración de runtime, prueba de concurrencia PostgreSQL, programación de mantenimiento, durabilidad multi-worker, búsqueda de restos en tmpfs/logs/DB y captura de egreso que confirme ausencia de archivo/contenido hacia terceros. Las pruebas unitarias del protocolo o almacenamiento no prueban namespaces ni runtime.
