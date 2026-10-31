# Fase 5 adelantada — frontend visual

Fecha: 30 de octubre de 2026. El usuario aprobó adelantar una vista visual desconectada sin terminar el backend. No se declara completa la Fase 5 de U2 ni OBJ-04.

## Hecho

- Frontend React 18 + TypeScript + Vite + Tailwind, en `frontend/`. Dirección original «El sandbox de vidrio», sin copiar marcas, personas ni activos de las referencias.
- Inicio y secciones adaptables, navegación móvil, tarjetas informativas y demo local de carga → análisis → resultado con nombres y datos ficticios. No hay selector de archivos, lectura, envío ni petición a la API; la interfaz señala que no existe procesamiento real.
- Cubo 3D minimalista con three.js local, sin partículas. Movimiento se detiene automáticamente antes de cinco segundos; `prefers-reduced-motion` lo desactiva. SVG local si falla el inicio de WebGL o se pierde el contexto; gestión de recursos al desmontar.
- Demo navegable por teclado: cambio de etapa mueve foco al panel, botones con `aria-pressed`, menú cerrable con Escape y foco devuelto. Riesgo con texto e iconos, no solo color.
- La primera revisión independiente señaló animación continua, falta de fallback tras pérdida de contexto y repintado tras redimensionar. Se corrigieron y la revisión final no encontró bloqueos; no fue una auditoría de accesibilidad completa.

## Evidencia

- `npm test`: **2 archivos, 5 pruebas pasaron**. Incluyen recorrido de demo, categorías, menú y fallback por fallo de inicio WebGL.
- `npm run build`: type-check y build Vite pasaron. Aviso real: chunk diferido de escena **542.52 kB** (>500 kB; gzip 134.59 kB). JS inicial 162.89 kB (gzip 53.15 kB). No se oculta el aviso ni se afirma que el rendimiento cumpla la meta.
- `npm audit --audit-level=high`: **0 vulnerabilidades** reportadas en esta ejecución.
- Vista local inspeccionada en navegador a 1440×900 y 390×844; cubo visible en escritorio, menú móvil y cierre con Escape, navegación del ejemplo hasta riesgo medio. No equivale a auditoría exhaustiva de dispositivos o lectores de pantalla.
- Se usó red para instalar paquetes de npm; assets y librerías se empaquetan localmente. La captura de tráfico que pruebe ausencia de terceros aún está pendiente.

## Pendiente y límites

- Medir FPS durante 60 s en equipo objetivo; no hay resultado ni fallback automático por bajo FPS medido. No añadir partículas antes de la medición.
- Comprobar exhaustivamente contraste de la interfaz renderizada, teclado, lector de pantalla, movimiento reducido, tráfico y CSP de despliegue. La pérdida posterior de contexto está manejada, pero no tiene prueba automatizada específica.
- Conectar cuentas/API y hacer carga/análisis/descarga reales solo cuando existan backend y procesador; añadir mapa autoalojado y consentimiento real de VirusTotal después.
- `package-lock.json` generado contiene más de 3,000 líneas; no abrir un PR apilado que exceda el límite de 400 sin autorización expresa `size:exception`. La excepción de PR 4 no autoriza este nuevo PR.

## Cómo probar y revertir

Desde `frontend/`: `npm ci`, `npm test`, `npm run build`, `npm run dev`. El servidor de desarrollo es local. Para revertir solo esta unidad, retirar `frontend/`, la entrada de `frontend/dist/` en `.gitignore` y las referencias de frontend en README y este reporte/ODD; los PR de backend permanecen intactos.
