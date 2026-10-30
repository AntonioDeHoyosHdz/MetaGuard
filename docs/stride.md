# Modelo STRIDE de MetaGuard

**Propósito:** registrar amenazas de OBJ-01 con control y prueba verificable. **Estado:** análisis de diseño; controles y pruebas descritos aquí son propuestas, no evidencia de implementación.

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

## Qué pasa si falta

Sin una amenaza, control y prueba enlazados, los riesgos quedan en afirmaciones sin dueño ni evidencia; no se puede mostrar qué protege cada límite de confianza.
