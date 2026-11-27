# Interfaz propuesta de MetaGuard

**Propósito:** describir pantallas, contenido e interacciones de OBJ-04 antes de implementar. **Estado:** wireframes textuales; copy, colores y tokens son propuestas.

## Flujo principal

`Inicio → Elegir archivo → Consentimiento opcional de reputación → Analizar → Resultado → Descargar copia limpia`

Navegación persistente: marca MetaGuard con símbolo geométrico propio; `Inicio`, `Cómo funciona`, `Privacidad`, `Actividad`; acción de sesión. No se reutiliza copy ni marca de las capturas.

## Pantallas y estados

| Pantalla | Boceto / acción | Vacío | Cargando | Error | Éxito |
|---|---|---|---|---|---|
| Inicio | Hero asimétrico: título tentativo “Comparte con privacidad”, botón de teclado/arrastrar archivo y cubo de vidrio con etiquetas sintéticas. | Área de carga con formatos admitidos JPG/PNG/PDF y límites pendientes de aprobación. | No muestra progreso hasta seleccionar y enviar. | Tipo/tamaño no admitido con explicación y acción para reintentar. | Archivo seleccionado, nombre escapado como texto y tamaño; acción “Analizar”. |
| Carga | Dropzone con botón `Elegir archivo`; no depende de arrastrar. | Instrucciones de formato/límite. | Barra real si el servidor informa progreso; de lo contrario indicador indeterminado, no porcentaje inventado. | Red/límite/tipo: mensaje claro sin ruta del servidor ni contenido. | Recibo temporal y siguiente paso de análisis. |
| Consentimiento VirusTotal | Diálogo separado, no preseleccionado: explica que saldrían solo SHA-256 original/limpio y que el hash revela que se consultó el archivo. | Consentimiento desactivado por defecto. | Solicitud de consentimiento registrándose; el análisis básico no queda bloqueado. | Fallo al registrar preferencia, consultar con cancelación segura. | “Consultar reputación” aceptado para ese archivo; también disponible “Continuar sin consultar”. |
| Análisis | Panel de pasos: tipo validado → sandbox → metadatos → verificación. Cubo representa el proceso, no certifica el resultado. | Espera de un archivo autorizado. | Mostrar estado del backend; no simular porcentajes ni afirmar que un paso terminó antes de su respuesta. | Timeout/aislamiento/servicio externo: indicar qué etapa falló y si se conserva o purga el archivo. | Reporte listo; transición visual menor a 400 ms. |
| Resultado | Resumen alto/medio/bajo con palabra + icono + color; tabla antes/después. Mapa autoalojado si se encontró GPS, visible solo al usuario dueño. | “No se encontró ese tipo de dato” sin afirmar ausencia total más allá de verificadores. | Cargando reporte/teselas locales, separado del análisis. | Reporte vencido o mapa no disponible; mantiene el resultado textual y permite borrar. | Valores antes/después, incertidumbres del verificador y acción de descarga de un uso. |
| Descarga | Botón grande “Descargar copia limpia”; indica vencimiento temporal. | Sin resultado limpio. | Generación/consumo del token sin exponerlo en pantalla/log. | Token vencido/usado: analizar de nuevo, si el archivo aún existe; si expiró, volver a cargar. | Descarga completada y confirmación de purga. |
| Actividad de cuenta | Lista de eventos propios, fecha, tipo e IP según permisos. | “Aún no hay eventos”. | Skeleton sin mostrar otra cuenta. | Error de autorización/red con CTA seguro. | Evento reciente; botón para revisar sesiones/asegurar cuenta. |
| Aviso de privacidad | Resumen simple con enlaces a finalidades, plazos, contacto y derechos; antes del registro. | Contacto responsable pendiente; no presentar como publicación final. | Carga local. | Aviso no disponible: bloquear registro hasta mostrarlo. | Usuario puede abrir versión completa y continuar con consentimiento informado. |

## Interacción y accesibilidad

- Teclado: tabulación visible, `Enter`/`Space` equivalen a seleccionar/continuar, `Escape` cierra diálogos sin activar consentimiento.
- Lectores de pantalla: regiones `aria-live` para estados de carga/resultado, foco al título de error, texto alternativo para mapa y modelo 3D.
- Riesgos siempre usan etiqueta (“Alto/Medio/Bajo”), icono y color. No usar color como única señal.
- Movimiento: cambios de estado 160–320 ms; `prefers-reduced-motion` apaga parallax, rotación y scroll reveal y conserva la misma información.
- Diseño adaptable: columna única en móvil; controles de carga y consentimiento de ancho completo; el mapa puede colapsarse pero el riesgo textual no.
- El nombre del archivo se codifica como texto; no se inserta como HTML. Datos reales de GPS/autor nunca alimentan el arte decorativo de la portada.

## Qué pasa si falta

Sin estados y equivalentes accesibles, una falla de carga puede parecer éxito, el riesgo puede perder significado sin color y usuarios de teclado/lector de pantalla quedar excluidos.
