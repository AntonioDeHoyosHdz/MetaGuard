# Límites operativos — aprobados para demo

Estos valores se aprobaron como punto de partida para la demo el 30 de octubre de 2026. La API aplica límites locales por proceso y el supervisor fija límites del contenedor; la aprobación no acredita capacidad ni eficacia en producción.

| Recurso | Valor inicial aprobado para demo | Justificación | Decisión |
|---|---:|---|---|
| Archivo JPG/PNG/PDF | Máximo 25 MiB por archivo | Acota transferencia y duplicación en memoria; uniforme para simplificar el primer corte. | APROBADO PARA DEMO; probar |
| Imagen | Máximo 8,000 px por lado y 40 megapíxeles | Un raster RGBA de 40 MP ronda 160 MiB antes del overhead; margen para limitar expansión bajo un cgroup. | APROBADO PARA DEMO; probar |
| PDF | Máximo 100 páginas | Limita costo por página; no evita por sí solo PDFs comprimidos/bomba. | APROBADO PARA DEMO; probar |
| Procesamiento | 60 s de pared por archivo | Falla rápido ante parser colgado; debe acompañarse de CPU/memoria y terminación forzada. | APROBADO PARA DEMO; probar |
| Worker | 1 vCPU, 1 GiB RAM y 1 trabajo activo por contenedor | Punto de partida conservador para demo; validar con corpus y hardware real. | APROBADO PARA DEMO; probar |
| Análisis en la API | 1 análisis activo por proceso API (`METAGUARD_WORKER_CONCURRENCY`), sin cola de admisión | Aplica contrapresión antes de descifrar la subida y limita la cantidad de análisis simultáneos en la API. | IMPLEMENTADO; medir en demo |
| Temporal del contenedor | `/tmp` en tmpfs de 64 MiB; sin mounts del host; raíz de solo lectura. | El procesador actual trabaja en memoria; tmpfs queda como espacio efímero acotado, no como almacenamiento de entrada. | IMPLEMENTADO EN CONFIGURACIÓN; verificar en runtime |
| API general | 60 solicitudes/min/IP y 120/min/cuenta autenticada | Límite local con excepciones por operación. El tratamiento de cabeceras de IP depende del borde de despliegue. | IMPLEMENTADO LOCALMENTE; validar en staging |
| Registro | 5 solicitudes/h/IP | Reduce creación automatizada; medir falsos positivos antes de producción. | IMPLEMENTADO LOCALMENTE; medir |
| Subida | 3/min/IP y 10/h/cuenta | Reduce presión sobre el worker. | IMPLEMENTADO LOCALMENTE; medir |
| Inicio de sesión | Tras 5 fallos del mismo par cuenta+IP: 1, 5 y 15 min | Objetivo de U2. El limitador de desarrollo cuenta intentos por proceso, no fallos consecutivos ni bloqueo progresivo. | OBJETIVO PENDIENTE |

Cuando no hay capacidad, `POST /v1/analyses/{upload_id}` devuelve `503` (`processing_busy`) con `Retry-After: 1` tras validar autenticación y titularidad. No lee ni borra el archivo temporal; el cliente puede reintentar con el mismo identificador antes del vencimiento. El encabezado indica cuánto esperar como mínimo, no cuándo habrá un cupo libre.

Este límite es local a cada proceso API. No reemplaza los límites del supervisor privado, las cuotas por cuenta o IP ni los controles del proxy, y no coordina el cupo entre réplicas.

## Verificación pendiente de capacidad y staging

1. Medir p95 de procesamiento del corpus en el equipo de demo y aumentar solo con justificación.
2. Probar imágenes expandibles/PDF bomba dentro de los límites de CPU/RAM/tiempo.
3. Confirmar límites de almacenamiento temporal, concurrencia, cuotas de usuario y proxy. El supervisor configura `--network=none`, `--read-only`, usuario 65532, `--cap-drop=ALL`, `no-new-privileges`, 1 GiB/1 vCPU, 64 PIDs, 60 s y tmpfs de 64 MiB. El [ensayo Docker local](validacion-staging.md#estado-observado) comprobó procesamiento sintético sin red, con raíz de solo lectura y UID no privilegiado; no midió capacidad ni validó el IPC nativo de staging.
4. Revisar límites junto con Nginx y API para que no se contradigan.

## Qué pasa si falta

La aprobación permite implementar estos valores como límites iniciales de demo; no demuestra que sean suficientes. Sin pruebas con el corpus, límites de CPU/RAM/tiempo y proxy, no se puede afirmar que archivos extremos no derriben el servicio. No son defaults de producción.
