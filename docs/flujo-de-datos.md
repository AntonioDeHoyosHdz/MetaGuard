# Flujo de datos de MetaGuard

**Propósito:** definir el recorrido, cifrado y borrado de una carga, conforme a OBJ-01 y al ciclo de datos U2. **Estado:** están implementadas la primitiva privada `InMemoryTemporaryFileStore` y las rutas T3d2 de carga/análisis para dependencias inyectadas y pruebas sintéticas. La ruta no dispone de runtime productivo, clave productiva, proveedor VirusTotal ni evidencia de ejecución real del sandbox. El store cifra en memoria con AES-256-GCM, liga contenido a IDs/propietario, aplica un límite de bytes y vencimiento de 10 minutos según la hora UTC del llamador; no escribe archivos ni promete durabilidad entre procesos o borrado físico de memoria. Descarga, reportes persistidos, purga programada y prueba de retención siguen pendientes.

## Los cinco pasos

| Paso | Recorrido y control | Dato / retención |
|---|---|---|
| 1. Recibir | Navegador → Nginx por TLS. Nginx limita cuerpo y tasa, descarta cabeceras de IP del cliente y establece la IP según la topología confiable. | Solicitud y archivo no confiables. |
| 2. Aceptar | La API valida sesión vigente, Origin/CSRF exactos y límites inyectados; recibe bytes crudos con `Content-Type` allowlist y comprueba el límite configurado mientras consume el stream. No decodifica multipart ni analiza bytes de archivo. Guarda el original mediante `InMemoryTemporaryFileStore` y un runtime inyectado. | Cifrado AES-256-GCM en memoria, ligado a propietario/ID; vencimiento de 10 min según reloj UTC inyectado. La aplicación por defecto no inyecta store ni llave y devuelve `503`. No se calcula SHA-256 en esta ruta. |
| 3. Procesar | La ruta verifica el dueño y llama solo al `ProcessingClient` API-side inyectado; FastAPI no invoca Docker ni parser. El contrato privado del supervisor/worker sigue siendo la frontera prevista. | Solo el runtime externo configurado podría ejecutar IPC/sandbox; no hay prueba de runtime Docker, aislamiento, red o límites en esta tarea. No se afirma que el contenido claro nunca toque disco fuera de esa prueba. |
| 4. Reportar | T3d2 devuelve en la respuesta únicamente el `ProcessingReport` minimizado del procesador; no persiste el reporte ni la copia limpia. Acepta `virus_total_consent` por archivo con default `false`, pero no existe proveedor conectado aquí. | No hay consulta VirusTotal ni claim de seguridad/ausencia de antecedentes. Retención de reportes 24 h, copia limpia temporal y caché siguen siendo diseño pendiente de T3d3. |
| 5. Descargar/purgar | API emite token de descarga de un uso, con vencimiento a los 10 min. Al descargar, borra la copia; una tarea de purga elimina lo vencido. | Evento de descarga/purga sin contenido del archivo. |

## Flujos laterales y reglas

- HIBP se limita a verificación de contraseña en registro/cambio: solo prefijo de 5 caracteres SHA-1 con padding; comparación local. No forma parte del procesamiento de archivos.
- Reportes cifran valores sensibles por campo. Eventos de seguridad se conservan 30 días y cada usuario solo consulta los propios.
- No registrar cuerpo, contenido extraído, contraseña, hash completo de contraseña, token de sesión/descarga ni llaves. Minimizar también nombre original y errores de parser.
- El borrado al expirar requiere un proceso programado y evidencia de prueba; la retención en memoria no se presume por la sola configuración de un contenedor.

## Qué pasa si falta

Sin este mapa se pierden de vista copias temporales, terceros, claves y plazos; no se puede demostrar minimización ni purga.

## Verificación

La primitiva privada tiene pruebas sintéticas de cifrado, ownership, límites, reloj y purga. T3d2 agrega pruebas de rutas con almacenamiento y procesador simulados: carga binaria, límite, Origin/CSRF, sesión, rate limiter, propiedad del upload, forma minimizada del reporte y fallas fail-closed. Estas pruebas no son evidencia de runtime ni retención de producto. Siguen pendientes: ejecución real de Docker, límites y aislamiento de la imagen construida, integración de runtime, descarga, persistencia y purga de reportes/copias, vencimiento en runtime, borrado tras descarga, búsqueda de restos en tmpfs/logs/DB y captura de egreso que confirme ausencia de archivo/contenido hacia terceros. Las pruebas unitarias del protocolo o del almacenamiento no prueban namespaces ni el runtime.
