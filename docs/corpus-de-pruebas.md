# Corpus de pruebas reproducible — especificación

**Propósito:** hacer medibles OBJ-03, OBJ-05 y OBJ-06 con entradas controladas. **Estado:** inventario planeado; no se ha generado ni probado el corpus.

## Composición objetivo

| Conjunto | Cantidad | Contenido / anotación esperada |
|---|---:|---|
| Imágenes JPG/PNG | 20 | Reparto JPG/PNG por decidir; sembrar GPS, fecha/hora, autor, serial, rutas, miniatura y campos de riesgo medio/bajo; registrar fixture, campos esperados y SHA-256. |
| PDF con contenido activo | 10 | JavaScript, `/OpenAction`, `/AA`, `/Launch`, `/GoToR`, `/SubmitForm`, `/ImportData`, `/RichMedia`, `/XFA`, `/EmbeddedFiles` y anotaciones de archivo; incluir nombres codificados y objetos comprimidos. Un índice marca cada muestra/objeto. |
| Casos de contraseña filtrada | 20 | No guardar contraseñas reales en el repositorio. Definir si serán entradas sintéticas de un servidor HIBP simulado o un corpus externo controlado: **decisión pendiente**. |

## Generación y evidencia

- Script determinista con semilla fija, manifiesto versionado (ID, formato, campos sembrados, esperado, hash del fixture), licencia/origen de assets y pasos reproducibles.
- PDFs de prueba aislados, no abrir en lector interactivo; generar con librerías/scripts de test y validar estructura con herramientas en sandbox.
- Para pruebas de HIBP, usar un mock local que entregue respuestas controladas y verificar que la integración envía solo prefijo SHA-1 con padding. No consultar servicio externo desde pruebas por defecto.
- Evitar contenido de usuarios reales y secretos. Corpus de prueba jamás representa garantía general sobre todos los archivos.
- Los resultados se publican solo después de ejecutar herramientas independientes: ExifTool/qpdf y pruebas automáticas. No hay resultados todavía.

## Qué pasa si falta

Sin corpus con verdad de terreno conocida no se puede medir 100% de limpieza/neutralización ni reproducir fallos. Fixtures sin procedencia o manifiesto tampoco prueban los criterios.
