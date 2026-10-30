# Flujo de datos de MetaGuard

**Propósito:** definir el recorrido, cifrado y borrado de una carga, conforme a OBJ-01 y al ciclo de datos U2. **Estado:** diseño propuesto, no ejecutado.

## Los cinco pasos

| Paso | Recorrido y control | Dato / retención |
|---|---|---|
| 1. Recibir | Navegador → Nginx por TLS. Nginx limita cuerpo y tasa, descarta cabeceras de IP del cliente y establece la IP según la topología confiable. | Solicitud y archivo no confiables. |
| 2. Aceptar | API autentica/autoriza, aplica límites, transmite el cuerpo sin parsear el formato y calcula SHA-256. Mantiene el archivo cifrado AES-256-GCM en memoria/temporal en memoria. | Original cifrado; máximo 10 min; todavía no se consulta ningún tercero. |
| 3. Procesar | Un canal local aún por definir entrega el insumo al contenedor sin red. Allí se valida tipo real/dimensiones, se extrae, limpia y verifica. | En el sandbox puede existir texto claro en memoria durante el procesamiento; no debe persistir en disco. |
| 4. Reportar | API guarda reporte y copia limpia temporal. Solo con consentimiento explícito por archivo, consulta VirusTotal usando SHA-256 del original y copia limpia. | Reporte 24 h o borrado manual; copia limpia máximo 10 min; caché de hash/veredicto 24 h. |
| 5. Descargar/purgar | API emite token de descarga de un uso, con vencimiento a los 10 min. Al descargar, borra la copia; una tarea de purga elimina lo vencido. | Evento de descarga/purga sin contenido del archivo. |

## Flujos laterales y reglas

- HIBP se limita a verificación de contraseña en registro/cambio: solo prefijo de 5 caracteres SHA-1 con padding; comparación local. No forma parte del procesamiento de archivos.
- Reportes cifran valores sensibles por campo. Eventos de seguridad se conservan 30 días y cada usuario solo consulta los propios.
- No registrar cuerpo, contenido extraído, contraseña, hash completo de contraseña, token de sesión/descarga ni llaves. Minimizar también nombre original y errores de parser.
- El borrado al expirar requiere un proceso programado y evidencia de prueba; la retención en memoria no se presume por la sola configuración de un contenedor.

## Qué pasa si falta

Sin este mapa se pierden de vista copias temporales, terceros, claves y plazos; no se puede demostrar minimización ni purga.

## Verificación

Pruebas pendientes: reloj/caducidad, borrado tras descarga, borrado tras expiración, búsqueda de restos en tmpfs/logs/DB, y captura de egreso que confirme ausencia de archivo/contenido hacia terceros.
