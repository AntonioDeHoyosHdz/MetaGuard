# Fase 2 — Diseño visual

Fecha: 30 de octubre de 2026. Alcance: especificación/documentación visual de OBJ-04; no se implementó frontend.

## Hecho y evidencia

- 4/4 artefactos redactados: `docs/diseno/metaguard-design-spec.json`, `decisiones.md`, `interfaz.md` y `escena-3d.md`.
- Dirección original “El sandbox de vidrio”: caja 3D de privacidad, marcadores abstractos de metadatos, paleta azul petróleo/menta y copy tentativo en español. Las imágenes del usuario se usaron como guía general de profundidad/3D/transiciones, no se copiaron composiciones, textos, marcas, personas o monedas.
- JSON parseado correctamente; 14 pares foreground/background calculados con script local Python 3 usando la fórmula WCAG. Resultado final: 14/14 pasan los mínimos indicados (texto normal 4.5:1; borde esencial 3:1).
- Ajuste real: borde inicial `#5B838B` sobre superficie elevada `#173943` falló en 2.97:1. Se cambió a `#628B94`; el par final dio 3.31:1 y pasó.
- Se usan fuentes del sistema; no hay fuente externa que autoalojar/licenciar en este borrador. Si luego se selecciona una fuente adicional, verificar licencia antes de incluirla.
- Transición de página propuesta: 320 ms (<400 ms); reduced motion desactiva parallax/rotación/partículas.

## Parcial / no verificado

| Área | Resultado |
|---|---|
| OBJ-04 — UI/visual | Diseño redactado; frontend y flujo real NO implementados. Éxito funcional verificado: 0%. |
| 3D/FPS | Meta propuesta ≥55 FPS desktop durante 60 s; NO MEDIDA, no hay frontend. Cubo primero; partículas solo después de medir. SVG es fallback. |
| Contraste | Se verificó la paleta candidata, no la UI renderizada completa. Revisar todos los nuevos pares cuando exista frontend. |
| Accesibilidad | Se especificaron teclado, lectores de pantalla, riesgo no solo por color y reduced motion; auditoría real de UI pendiente. |
| Tráfico/CSP/mapa | No hay frontend ni captura; uso de assets locales y mapa autoalojado siguen requisitos de implementación. |

## Riesgos y preguntas abiertas

1. Los tokens, textos, breakpoints y FPS son propuestas para aprobación, no valores finales de diseño ni mediciones.
2. No iniciar implementación de Fase 3 hasta recibir aprobación visual y completar las decisiones de límites/fechas pendientes de fases anteriores.
3. Confirmar si el cubo de vidrio y la paleta azul petróleo/menta representan bien MetaGuard antes de construirlos.

## Historial y cierre

Se publicaron commits pequeños en la rama `docs/phase2-visual-design`, todos con fecha real del 30-10-2026; no se falsificaron ni reescribieron fechas/autores. [PR 3](https://github.com/AntonioDeHoyosHdz/MetaGuard/pull/3) está abierto sobre `docs/phase1-02-api-ops`, dentro del presupuesto de 400 líneas; no se hizo merge. `gh pr checks 3` devolvió “no checks reported” (salida 1), por lo que no se afirma un resultado CI. Esperar aprobación del usuario antes de Fase 3.
