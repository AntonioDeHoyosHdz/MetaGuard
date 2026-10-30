# Decisiones visuales de MetaGuard

**Propósito:** justificar una dirección visual original para OBJ-04 y conectarla con el flujo de privacidad. **Estado:** propuesta para revisión; no es UI implementada.

| Decisión | Motivo | Alternativa descartada | Relación con el flujo |
|---|---|---|---|
| Espacio profundo azul petróleo y acentos menta | Comunica calma y tecnología de seguridad sin parecer un panel de trading. | Copiar el cielo, la persona y las monedas de las capturas. | El foco visual recae en archivos, límites y resultados, no en inversión/cripto. |
| Caja de vidrio como objeto central | Hace tangible el aislamiento del procesador y permite mostrar sus límites. | Escudo genérico flotante o fotografía de stock. | El archivo entra al sandbox visual y sale solo tras una respuesta real del backend. |
| Etiquetas abstractas de metadatos (GPS, autor, cámara) | Explica qué clase de dato se detectó sin mostrar valores personales reales. | Monedas/tokens con logotipos o coordenadas de una persona. | Las etiquetas se apartan del archivo solo cuando el resultado confirma el saneamiento. |
| Composición hero asimétrica propia: copy a la izquierda, cubo a la derecha | Mantiene una lectura rápida y una pieza 3D reconocible en escritorio; no replica la composición de referencia. | Reproducir el recorte de persona/cielo ni la secuencia visual de las capturas. | El botón “Analizar archivo” inicia el flujo de carga. Texto tentativo: “Comparte con privacidad”. |
| Paleta oscura con riesgo rojo/ámbar/verde más texto e icono | Conserva contraste y no reduce riesgo a color. | Colores luminosos sin semántica o rojo/verde solos. | Alto/medio/bajo aparecen en análisis y reporte con palabra visible e icono. |
| Fuentes del sistema: Georgia para títulos y system-ui para interfaz | Evita descarga de fuentes, dependencia de CDN y revisión de licencias de fuentes externas en esta iteración. | Autoalojar una fuente no seleccionada/verificada. | Hace legibles encabezados y controles sin sumar tráfico externo. |
| Movimientos entre 160–320 ms con easing definido | La interfaz se siente fluida sin retrasar una tarea de seguridad. | Animaciones largas, parallax fuerte o movimiento continuo obligatorio. | Acompaña carga/resultado; el estado real siempre está disponible sin esperar la animación. |
| `prefers-reduced-motion` quita bucles y parallax | Respeta preferencias de movimiento y reduce distracciones. | Mantener rotación/scroll reveal para todos. | El flujo sigue siendo entendible con fundidos cortos y estados textuales. |
| Mapa con teselas autoalojadas; sin fuentes/activos remotos | La zona GPS no debe delatarse a un proveedor de mapa. | Teselas externas o imágenes/código por CDN. | Resultado puede ubicar el hallazgo localmente sin tercero; depende de infraestructura aprobada. |
| SVG como respaldo de escena 3D | El análisis debe seguir siendo rápido y accesible si el dispositivo no sostiene FPS. | Forzar WebGL o bloquear cargas en equipos modestos. | El flujo de archivo funciona aunque el adorno 3D se desactive. |

## Accesibilidad y contraste

La especificación incluye 14 pares foreground/background calculados localmente con la fórmula de luminancia relativa WCAG. Texto normal: mínimo 4.5:1; bordes esenciales de controles: 3:1. Todos los pares finales pasan; una primera propuesta de borde (`#5B838B` sobre `#173943`, 2.97:1) falló y se ajustó a `#628B94` (3.31:1). Valores y resultados exactos: `metaguard-design-spec.json`.

## Qué pasa si falta

Sin motivo/alternativa/relación funcional, el equipo puede copiar referencias, añadir animación que oculta el estado real o filtrar información privada por una escena/servicio innecesario.
