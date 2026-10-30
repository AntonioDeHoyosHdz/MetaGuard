# Clasificación propuesta de riesgo de metadatos

**Propósito:** explicar el riesgo por campo para el análisis de OBJ-03. **Estado:** clasificación de trabajo tomada del prompt MetaGuard; debe confirmarse contra archivos de prueba y alcance final.

| Nivel | Campo / grupo | Por qué importa | Presentación prevista |
|---|---|---|---|
| Alto | GPS/coordenadas | Puede revelar domicilio, rutina o ubicación exacta. | Nombre claro, valor sensible minimizado/cifrado y advertencia. |
| Alto | Fecha y hora | Puede correlacionar presencia, rutina o secuencia de actividad. | Mostrar solo si es necesario para explicar el hallazgo. |
| Alto | Número de serie | Puede identificar de forma persistente un dispositivo o vincular archivos. | Ocultar valor completo en pantalla/logs. |
| Alto | Autor/propietario | Puede identificar a una persona o revelar afiliación laboral. | No exponer más que lo necesario al usuario autenticado. |
| Alto | Rutas/nombres de directorio | Pueden revelar nombre de usuario, organización o estructura interna. | Escapar como texto; ocultar rutas en logs. |
| Alto | Miniatura incrustada | Puede retener una imagen original/recortada o contenido distinto al visible. | Reportar presencia/resultado sin publicar la miniatura. |
| Medio | Modelo de dispositivo | Reduce el conjunto de candidatos y ayuda a perfilar al usuario. | Explicar que contribuye a identificación indirecta. |
| Medio | Software de creación | Puede exponer herramienta/versión y entorno de trabajo. | Mostrar nombre saneado, no enlazar como HTML. |
| Medio | Notas del fabricante | Pueden contener datos técnicos o identificadores no estandarizados. | Tratar como no confiables; no registrar contenido completo. |
| Bajo | Perfil de color | Suele describir representación del color; normalmente identifica menos que un serial o ubicación. | Informar que se descarta al recomprimir; comprobar compatibilidad visual. |
| Bajo | Dimensiones | Informan tamaño/proporción, pero rara vez ubican o identifican por sí solas. | Conservar en reporte si es útil; no es una promesa de anonimato. |

“Bajo” no significa inocuo. La combinación de campos puede aumentar riesgo y el contenido visible (rostros, letreros, texto) queda fuera del alcance de limpieza automática.

## Qué pasa si falta

Sin razones por campo, el color del riesgo parece arbitrario y el usuario no puede distinguir metadatos identificadores de propiedades técnicas.
