# Límites operativos — aprobados para demo

**Propósito:** fijar límites que acoten consumo de recursos y abuso. **Estado:** el usuario aprobó todos los valores como configuración inicial de demo el 30 de octubre de 2026. No son mediciones ni valores aprobados para producción; su efectividad aún debe probarse.

| Recurso | Propuesta inicial | Justificación | Decisión |
|---|---:|---|---|
| Archivo JPG/PNG/PDF | Máximo 25 MiB por archivo | Acota transferencia y duplicación en memoria; uniforme para simplificar el primer corte. | APROBADO PARA DEMO; probar |
| Imagen | Máximo 8,000 px por lado y 40 megapíxeles | Un raster RGBA de 40 MP ronda 160 MiB antes del overhead; margen para limitar expansión bajo un cgroup. | APROBADO PARA DEMO; probar |
| PDF | Máximo 100 páginas | Limita costo por página; no evita por sí solo PDFs comprimidos/bomba. | APROBADO PARA DEMO; probar |
| Procesamiento | 60 s de pared por archivo | Falla rápido ante parser colgado; debe acompañarse de CPU/memoria y terminación forzada. | APROBADO PARA DEMO; probar |
| Worker | 1 vCPU, 1 GiB RAM y 1 trabajo activo por contenedor | Punto de partida conservador para demo; validar con corpus y hardware real. | APROBADO PARA DEMO; probar |
| API general | 60 solicitudes/min/IP y 120/min/cuenta autenticada | Límite inicial para demo, con excepciones por endpoint y cabecera de IP confiable. | APROBADO PARA DEMO; probar |
| Registro | 5 solicitudes/h/IP | Reduce creación automatizada; medir falsos positivos antes de producción. | APROBADO PARA DEMO; probar |
| Subida | 3/min/IP y 10/h/cuenta | Reduce presión del worker; agregar cuota concurrente después de medir. | APROBADO PARA DEMO; probar |
| Inicio de sesión | Tras 5 fallos del mismo par cuenta+IP: 1, 5 y 15 min | Coherente con OBJ-07 del prompt; no bloquear la cuenta por fallos desde IPs distintas. | APROBADO PARA DEMO; probar |

## Verificación pendiente antes de usar en demo

1. Medir p95 de procesamiento del corpus en el equipo de demo y aumentar solo con justificación.
2. Probar imágenes expandibles/PDF bomba dentro de los límites de CPU/RAM/tiempo.
3. Confirmar límites de almacenamiento temporal, concurrencia, cuotas de usuario y proxy.
4. Revisar límites junto con Nginx y API para que no se contradigan.

## Qué pasa si falta

La aprobación permite implementar estos valores como límites iniciales de demo; no demuestra que sean suficientes. Sin pruebas con el corpus, límites de CPU/RAM/tiempo y proxy, no se puede afirmar que archivos extremos no derriben el servicio. No son defaults de producción.
