# Corpus sintético reproducible

El corpus reúne **20 imágenes, 10 PDF inertes y 20 casos de contraseñas simuladas** para OBJ-03, OBJ-05 y parte de OBJ-06. Las entradas son sintéticas: no contienen datos personales ni secretos, no derivan de filtraciones y no se envían a ningún servicio externo.

## Reproducir la evidencia

Desde `backend`, con el entorno del proyecto ya instalado, generar los archivos en un directorio temporal nuevo y ejecutar las pruebas enfocadas:

```powershell
$corpus = Join-Path $env:TEMP ('metaguard-corpus-' + [Guid]::NewGuid())
uv run --offline --no-sync python tests/academic_corpus.py $corpus
uv run --offline --no-sync pytest -q --no-cov -p no:cacheprovider tests/test_academic_corpus.py
```

El [manifiesto versionado](../backend/tests/academic_corpus_manifest.json) indica las etiquetas sembradas, el resultado esperado y el SHA-256 de cada entrada. El [generador](../backend/tests/academic_corpus.py) crea los 30 archivos y una copia del manifiesto; no versionamos los binarios ni escribimos las entradas de contraseñas en disco. Para cada caso de contraseña, el hash identifica un registro JSON canónico con su ID, escenario y entrada sintética. Todos los archivos se generan por orden de ID, sin semilla aleatoria, reloj ni recursos de terceros. Si un hash difiere, comprobar las versiones del entorno antes de actualizar el manifiesto.

## Qué comprueba cada conjunto

| Conjunto | Diseño y comprobación |
|---|---|
| 10 JPG y 10 PNG | Valores conocidos de GPS, fecha, autor, número de serie, ruta, miniatura, modelo o software. Se comprueba la presencia de cada campo en la entrada, su ausencia en la salida y la categoría del reporte. El chequeo de contenedores comprueba también la ausencia de EXIF o texto sembrado. El PNG conserva los píxeles exactos; en JPEG se tolera una diferencia de hasta tres niveles por canal por la recompresión. |
| 10 PDF | Seis con un indicador estructural vacío y cuatro con un título como etiqueta, sin acción asociada. Se verifica qué debe desaparecer según el manifiesto. Poppler comprueba por separado que se elimina el título, se conserva una página y el render no cambia. No hay código, destinos externos, formularios ejecutables, archivos adjuntos ni variantes de evasión. |
| 20 casos de contraseña | Diez coincidencias, cuatro ausencias, dos coincidencias con conteo cero de relleno, dos fallos de servicio, una respuesta inválida y un rechazo local sin consulta. El transporte HTTP se sustituye en memoria: se comprueban `GET`, el prefijo SHA-1 de cinco caracteres y `Add-Padding: true`; no se envía el sufijo, contraseña ni cuerpo. Se comprueba el resultado y, cuando corresponde, el evento genérico de indisponibilidad. |

## Resultados y límites

Ejecución local del 21 de noviembre de 2026: **61 pruebas pasaron**, incluidas las diez comprobaciones independientes con Poppler 26.07.0. `Get-FileHash` confirmó los **30 SHA-256** de los archivos generados. Entorno observado: Python 3.13.5, Pillow 13.0.0 y pikepdf 10.18.2 (libqpdf 12.4.2). La opción `--no-cov` evita aplicar a una sola prueba el umbral de cobertura global del backend; esta ejecución no sustituye una suite completa.

ExifTool y el ejecutable `qpdf` no estaban disponibles. La inspección de campos con Pillow y de objetos con pikepdf usa las mismas bibliotecas que el procesador; la comprobación de contenedores no sustituye ExifTool, y el render de Poppler no sustituye una auditoría de objetos con `qpdf`. Estos resultados no prueban neutralización de archivos activos, reputación externa ni una integración en vivo con HIBP.
