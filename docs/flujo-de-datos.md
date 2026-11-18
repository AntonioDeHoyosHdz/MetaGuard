# Flujo de datos de MetaGuard

**Propósito:** definir el recorrido, cifrado y borrado de una carga, conforme a OBJ-01 y al ciclo de datos U2. **Estado:** diseño propuesto; solo está implementada la primitiva privada `InMemoryTemporaryFileStore` para cifrar en memoria AES-256-GCM, ligar contenido a IDs inmutables, aplicar un límite de bytes suministrado y vencimiento de 10 minutos con hora UTC del llamador. No hay rutas de carga/descarga, integración con API o supervisor, clave productiva, borrado programado ni evidencia de retención real; la primitiva no escribe archivos ni promete durabilidad entre procesos o borrado físico de memoria.

## Los cinco pasos

| Paso | Recorrido y control | Dato / retención |
|---|---|---|
| 1. Recibir | Navegador → Nginx por TLS. Nginx limita cuerpo y tasa, descarta cabeceras de IP del cliente y establece la IP según la topología confiable. | Solicitud y archivo no confiables. |
| 2. Aceptar (propuesto) | La futura API autentica/autoriza, aplica límites, transmite el cuerpo sin parsear el formato y calcula SHA-256. La única implementación actual es una primitiva privada de almacenamiento en memoria cifrado; todavía no hay ruta que la invoque ni configuración de clave productiva. | Requisito de diseño: original cifrado; máximo 10 min; todavía no se consulta ningún tercero. La expiración y purga de la primitiva aún no están conectadas a runtime. |
| 3. Procesar | El supervisor privado valida un esquema fijo de bytes+MIME y ejecuta el worker con opciones Docker fijas; el worker llama `process_file` sin recibir rutas, opciones, imagen, entorno ni comandos del cliente. | stdin/stdout transportan la entrada y salida. El sandbox no tiene red ni mounts, usa raíz de solo lectura y memoria/CPU/tiempo acotados. El texto claro permanece en memoria durante el procesamiento; no se escribe a disco. |
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

La primitiva privada tiene pruebas sintéticas de cifrado, ownership, límites, reloj y purga; no son evidencia de rutas ni retención de producto. Siguen pendientes: ejecución real de Docker, límites y aislamiento de la imagen construida, ruta de carga/descarga, integración de la purga, expiración en runtime, borrado tras descarga, búsqueda de restos en tmpfs/logs/DB y captura de egreso que confirme ausencia de archivo/contenido hacia terceros. Las pruebas unitarias del protocolo o del almacenamiento no prueban namespaces ni el runtime.
