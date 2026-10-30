# Escena 3D: el sandbox de vidrio

**Propósito:** convertir el aislamiento y el flujo de saneamiento en una metáfora entendible, no en una promesa técnica. **Estado:** concepto y presupuesto propuestos; no implementado ni medido.

## Concepto y elementos

- **Volumen principal:** cubo/caja de vidrio con bordes menta y una cámara clara; representa el contenedor de procesamiento sin red.
- **Entrada:** una tarjeta abstracta representa un archivo, nunca el contenido del usuario.
- **Marcadores:** iconos genéricos para ubicación, autoría y dispositivo; no muestran valores reales ni coordenadas.
- **Salida:** una forma limpia solo aparece después de que la API confirme resultado exitoso. Si falla, la escena muestra estado de error textual; nunca simula limpieza.
- **Luz:** una luz ambiental suave y una luz de borde; sombras y bloom son opcionales y deben justificarse por FPS.
- **Movimiento ambiental:** respiración/luz lenta de 8 s en escritorio, solo si no hay preferencia de movimiento reducido; interacción de puntero limitada a una inclinación sutil.

## Secuencia

| Estado real de la app | Animación | Condición |
|---|---|---|
| Inicial | Caja quieta, marcadores flotan apenas | Escena cargada; el formulario sigue operable si WebGL falla. |
| Archivo seleccionado | Tarjeta entra y queda en espera | Selección local; no afirmar que se subió antes de respuesta de API. |
| Procesando | Cámara del cubo cierra; marcadores se atenúan | Backend confirma etapa; indicador de texto paralelo. |
| Limpieza verificada | Los marcadores se separan, sale tarjeta abstracta | Solo después de resultado verificado del backend. |
| Error / expiración | Caja se abre o queda neutra; acción de reintento | Fallo real comunicado por API; no animar estado de éxito. |

Transiciones UI de 160–320 ms; ninguna transición de página excede 400 ms. Movimiento 3D continuo no bloquea la interacción ni comunica porcentaje ficticio.

## Presupuesto y degradación

1. **Etapa A:** cubo, núcleo y luz; sin partículas. Perfilar FPS durante 60 s en desktop objetivo.
2. **Meta propuesta:** ≥55 FPS sostenidos en escritorio. Aún no medida porque no hay frontend.
3. Solo si Etapa A cumple la meta, probar hasta 16 partículas ligeras y medir de nuevo. Si cae por debajo del objetivo, eliminar partículas.
4. Si WebGL no existe o el rendimiento no se sostiene, cambiar automáticamente a SVG estático equivalente. Nada de CDN: three.js y recursos deben empaquetarse localmente.

## Accesibilidad y seguridad

- `prefers-reduced-motion`: sin rotación, parallax, partículas ni movimiento ambiental; solo fundido de hasta 120 ms.
- Alternativa textual: “Archivo en sandbox”, estado actual y resultado accesibles por lector de pantalla; la escena es decorativa (`aria-hidden`).
- La escena usa datos sintéticos de ejemplo. No filtra nombre del archivo, GPS, autor ni resultados a telemetría/servicios externos.
- Contraste de etiquetas coincide con los pares auditados en `metaguard-design-spec.json`; icono/etiqueta permanecen visibles si se desactiva 3D.

## Qué pasa si falta

Sin presupuesto y fallback, un adorno 3D puede bajar FPS, impedir carga en móvil, ocultar errores o aparentar una protección que el procesador no confirmó.
