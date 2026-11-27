# Modelo STRIDE de MetaGuard

**Propósito:** registrar amenazas de OBJ-01 con control y prueba verificable. **Estado:** el modelo de diseño se contrasta abajo con pruebas locales de la implementación. La evidencia no acredita el perímetro público ni sustituye la revisión del entorno.

## Amenazas y pruebas previstas

| ID | Amenaza | STRIDE | Componente | Control previsto | Prueba que debe verificarlo |
|---|---|---|---|---|---|
| T-01 | Archivo hostil explota un parser | Elevation of Privilege | Procesador | Sandbox sin red/privilegios, FS RO, límites de recursos, parsers actualizados | Fixture hostil no accede al host/red y el contenedor termina aislado. |
| T-02 | PDF bomba agota CPU/memoria | Denial of Service | Procesador | Límite de páginas, tiempo, CPU y memoria; cola limitada | PDF bomba se detiene dentro de límites; otros trabajos y API siguen disponibles. |
| T-03 | Cliente falsifica `X-Forwarded-For` para evadir cuota | Spoofing | Nginx/API | Proxy elimina cabeceras de origen y API confía solo en proxy propio | Variar cabeceras falsas no cambia la IP usada para el rate limit. |
| T-04 | Token de descarga vencido/reutilizado permite descargar | Elevation of Privilege | Descarga/API | Token de un uso, 10 min, ligado al recurso/usuario; borrar tras descargar | Segundo uso y uso posterior a expiración fallan; archivo ya no existe. |
| T-05 | Fuerza bruta distribuida bloquea o toma cuenta | Spoofing / DoS | Autenticación | Umbral por cuenta+IP, desafío adicional si varían IP; MFA y alertas | Cinco fallos del mismo par aplican 1/5/15 min; IP distinta no bloquea al usuario legítimo. |
| T-06 | BOLA/IDOR lee reporte/evento ajeno | Elevation of Privilege | API/DB | Autorización por objeto en cada operación; respuestas que no revelan existencia ajena | Usuario A solicita IDs de B en lista, detalle, borrado y descarga; recibe rechazo. |
| T-07 | Llave AES o secreto de servicio se filtra | Information Disclosure | API/secretos | No repositorio/logs; mínimo privilegio; rotación y respuesta a incidente documentadas | Escaneo de secretos más prueba de que un rol no autorizado no lee secretos. |
| T-08 | HIBP/VT/SMTP no disponible o responde lento | Denial of Service | Integraciones | HIBP: fallback de longitud mínima + lista local y evento; VT: estado no disponible, no “seguro”; SMTP: registrar falla sin fingir entrega | Simular timeout/5xx por servicio; comprobar fallback HIBP, estado VT, evento y ausencia de datos/secreto en egreso/log. |
| T-09 | Nombre de archivo ejecuta XSS almacenado/reflejado | Tampering | API/UI futura | Tratar como texto, codificar al renderizar, nunca interpolar HTML; CSP | Cargar nombre con payload y comprobar que no ejecuta en reporte/eventos. |
| T-10 | Robo de cookie JWT habilita suplantación | Spoofing | Navegador/API | HttpOnly, Secure, SameSite; CSRF; vida corta pendiente; invalidación y TLS | Verificar atributos, rechazo CSRF y cierre/invalidez tras logout según diseño final. |
| T-11 | Falta consentimiento y se revela hash a VirusTotal | Information Disclosure | API/VT | Opt-in explícito por archivo, hash únicamente, registro del consentimiento | Sin permiso no hay egreso; con permiso solo salen hashes autorizados. |
| T-12 | CSRF cambia estado o establece una sesión de login desde un sitio atacante | Tampering | API/autenticación | Token CSRF también en login/MFA preauth, validación de `Origin`, tokens SameSite; reautenticación en operaciones sensibles | Intento cross-site de login y de mutación sin token/origen válido se rechaza. |
| T-13 | API/proxy aceptan tipo declarado falso y tratan bytes como confiables | Tampering | Nginx/API/Worker | API no parsea; worker valida firma/tipo real en sandbox; límites de entrada | MIME/extensión engañosos se detectan/rechazan dentro del sandbox. |
| T-14 | Logs o errores revelan GPS, rutas, contraseñas o tokens | Information Disclosure | API/Worker | Lista de datos prohibidos en logs, mensajes genéricos, revisión de telemetría | Inyectar valores-canario y buscar que no aparezcan en logs/errores. |

## Supuestos y límites

El operador es confiable según U2; el atacante puede controlar archivos, solicitudes y cabeceras cliente. STRIDE es un inventario inicial, no certificación exhaustiva. Cada control debe enlazarse a implementación y prueba antes de marcar OBJ-01 cumplido.

## Evidencia local por amenaza

Los nombres de archivo enlazan las pruebas reutilizables. Las verificaciones con entradas sintéticas acreditan únicamente los controles indicados. Para los recorridos y límites del entorno, consulta [Validación de staging](validacion-staging.md).

| ID | Control comprobable y prueba | Pendiente en el entorno objetivo |
|---|---|---|
| T-01 | [Supervisor e IPC](../backend/tests/test_processing_supervisor.py): opciones de aislamiento del proceso e importación del trabajador con solo los módulos declarados en la imagen. [Identidad del par IPC](../backend/tests/test_processing_ipc_handler.py) rechaza pares no autorizados. | Validar el digest candidato, el aislamiento efectivo y el socket de la versión desplegada. |
| T-02 | [Procesador](../backend/tests/test_file_processing.py) limita páginas; [supervisor](../backend/tests/test_processing_supervisor.py) elimina el contenedor identificado tras un timeout simulado; [API](../backend/tests/test_file_routes.py) rechaza trabajos cuando no hay capacidad. | Observar la continuidad y los límites de la instancia candidata con cargas benignas y controladas. |
| T-03 | [Runtime de staging](../backend/tests/test_staging_runtime.py) comprueba que los encabezados de reenvío no cambian al par de transporte. [Configuración versionada](../deploy/staging/upstream.nginx.conf) elimina los encabezados de identidad del cliente. | Comprobar la cuota en el proxy efectivo. Detrás del proxy, el par directo no equivale a la dirección del visitante; no activar políticas por IP real sin verificar su origen confiable. |
| T-04 | [Rutas de reporte y descarga](../backend/tests/test_report_routes.py) comprueban digest, uso único, borrado al descargar y expiración a los diez minutos. | Verificar retención y purga operativa para las réplicas desplegadas. |
| T-05 | [Política de riesgo](../backend/tests/test_login_risk.py) prueba bloqueo progresivo y que el riesgo agregado no bloquea globalmente. [Rutas](../backend/tests/test_login_risk_routes.py) verifican el desafío y su no reutilización. | Activación con identidad confiable por visitante y entrega de alertas en el entorno de destino. |
| T-06 | [Reportes](../backend/tests/test_report_routes.py) y [eventos](../backend/tests/test_security_event_routes.py) comprueban listados por titular y rechazo de objetos ajenos. | Repetir con dos cuentas sintéticas en el despliegue candidato. |
| T-07 | [Lector de secretos](../backend/tests/test_secrets.py) comprueba errores sin valores ni rutas; [contexto Docker](../backend/tests/test_processing_supervisor.py) excluye nombres de secretos y llaves. | Escaneo sanitizado y comprobación de permisos del usuario efectivo de cada servicio. |
| T-08 | [Política local](../backend/tests/test_password_policy.py) prueba el respaldo ante indisponibilidad de HIBP; [rutas de archivo](../backend/tests/test_file_routes.py) preservan el análisis sin VirusTotal; [SMTP](../backend/tests/test_gmail_sender.py) no presenta como entregado un envío fallido. | Verificar continuidad y observabilidad con los transportes autorizados; las pruebas locales los simulan. |
| T-09 | [Pruebas de interfaz](../frontend/src/App.test.tsx) verifican que un nombre con ángulos permanece como texto, que la carga envía bytes sin un campo de nombre y que la descarga usa un nombre derivado del tipo. | Verificar la CSP servida y las rutas de reporte del despliegue candidato. |
| T-10 | [Autenticación](../backend/tests/test_auth_routes.py) comprueba atributos de cookies y revocación inmediata; [sesiones](../backend/tests/test_sessions.py) rechaza vencidas o revocadas. | Comprobar atributos y cierre en respuestas reales tras el proxy. |
| T-11 | [Análisis](../backend/tests/test_file_routes.py) verifica consentimiento explícito y solo dos huellas; [transporte](../backend/tests/test_virustotal.py) verifica GET al destino fijo y respuesta minimizada. | Capturar solamente metadatos del egreso permitido en un ensayo consentido. No hay historial persistido de consentimiento por archivo. |
| T-12 | [Inicio de sesión y MFA](../backend/tests/test_auth_routes.py) y [carga](../backend/tests/test_file_routes.py) verifican el origen exacto y su relación con CSRF. | Validar la configuración efectiva del proxy y los métodos que quedan expuestos. |
| T-13 | [Rutas de carga](../backend/tests/test_file_routes.py) limitan bytes; [procesador](../backend/tests/test_file_processing.py) rechaza entradas con formato real distinto al declarado. | Confirmar el camino desde la admisión de bytes crudos hasta el trabajador candidato: aceptar una carga no significa aprobar su formato. |
| T-14 | [Errores de autenticación](../backend/tests/test_auth_routes.py), [descarga](../backend/tests/test_report_routes.py), [procesamiento](../backend/tests/test_file_routes.py) y [mantenimiento](../backend/tests/test_maintenance.py) prueban que los errores y registros locales no reflejan canarios privados. | Revisar las salidas efectivas de proxy, API, trabajador y colector con canarios sintéticos. |

## Qué pasa si falta

Sin una amenaza, control y prueba enlazados, los riesgos quedan en afirmaciones sin dueño ni evidencia; no se puede mostrar qué protege cada límite de confianza.
