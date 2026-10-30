# Trazabilidad de la propuesta U2

Fecha de revisión: 30 de octubre de 2026. Alcance: inventario local del directorio de trabajo, sin implementar código.

## Objetivos y medidas de éxito

| Objetivo | Medida de éxito de la propuesta | Estado en el repositorio MetaGuard | Evidencia revisada |
|---|---|---|---|
| OBJ-01 — Arquitectura y amenazas | Diagramas de arquitectura y flujo con límites de confianza; matriz STRIDE con al menos 10 amenazas, cada una con control y prueba. | No existe | No se encontraron entregables de MetaGuard; únicamente la propuesta PDF y configuración local de Codex. |
| OBJ-02 — API segura | ≥12 endpoints; autenticación salvo públicos enumerados; ≥70% de cobertura; prueba contra IP falsificada y prueba de purga tras descarga/expiración. | No existe | No se encontró backend, OpenAPI ni pruebas. |
| OBJ-03 — Análisis y limpieza | Corpus de 20 archivos; 100% de campos de riesgo alto sembrados eliminados y verificados independientemente; composición documentada. | No existe | No se encontró motor, corpus, reporte ni verificador. |
| OBJ-04 — Frontend y seguridad | Flujo completo; ZAP, pip-audit, npm audit y Trivy sin hallazgos altos/críticos abiertos; captura sin peticiones de mapa a terceros; despliegue de un comando. | No existe | No se encontró frontend, infraestructura de MetaGuard, evidencia de escaneo ni captura. |
| OBJ-05 — Contraseñas filtradas | 20/20 rechazadas; captura que pruebe que solo sale prefijo SHA-1 de 5 caracteres con padding; fallback local probado con servicio caído. | No existe | No se encontró API de contraseñas ni pruebas/evidencia. |
| OBJ-06 — PDF activo | 10/10 PDFs de prueba neutralizados, incluidas variantes codificadas/comprimidas; verificación qpdf; solo hashes salen a VirusTotal con consentimiento. | No existe | No se encontró procesador PDF, corpus, prueba qpdf ni integración. |
| OBJ-07 — Monitoreo y alertas | 7 eventos; bloqueo progresivo tras 5 fallos por cuenta+IP; atacante desde otra IP no bloquea al usuario; alerta <1 min; aislamiento de eventos por usuario. | No existe | No se encontró sistema de eventos, alertas, interfaz ni pruebas. |

## Módulos funcionales (4)

| Módulo | Objetivo asociado | Estado |
|---|---|---|
| Limpieza y verificación de metadatos | OBJ-03 | No existe |
| Verificación de contraseñas filtradas | OBJ-05 | No existe |
| Detección/neutralización de PDF y reputación | OBJ-06 | No existe |
| Monitoreo y alertas de seguridad | OBJ-07 | No existe |

## Inventario

- Presente en la raíz: `U2_PropuestaProyecto_MetaGard_243776.pdf`, `.codex/` y `gentle-ai/`.
- `gentle-ai/` es un checkout Git separado del código de la herramienta Gentle; no se considera implementación de MetaGuard. La raíz de MetaGuard se inicializó como Git después del corte de Fase 0 y se publicó en el repositorio privado `https://github.com/AntonioDeHoyosHdz/MetaGuard`. Este cambio de gestión no altera el estado funcional de los objetivos.
- No se encontraron `backend/`, `frontend/`, `processor/`, `nginx/`, `docker-compose.yml`, `corpus/`, `README.md`, `AGENTS.md` en la raíz, `docs/diseno/metaguard-design-spec.json` ni materiales MetaGuard adicionales. `docs/` se creó durante esta fase.
- No se identificó contradicción entre artefactos implementados y la propuesta: no hay artefactos de implementación para comparar. La clasificación por campo, el diseño visual y las decisiones de límites aún no están definidos/confirmados.

## Datos retenidos (sección 3.2 de la propuesta)

| Dato | Finalidad | Retención | Protección indicada |
|---|---|---|---|
| Archivo subido y copia limpia | Procesamiento y descarga | Máximo 10 minutos; se borra al descargar o expirar | Memoria o carpeta temporal en memoria; AES-256-GCM; token de descarga de un solo uso |
| Reporte de análisis | Mostrar antes/después | 24 horas o borrado manual | Valores sensibles (GPS, serie, autor) cifrados por campo con AES-256-GCM |
| Eventos de seguridad (incluida IP) | Monitoreo y alertas | 30 días | Cada usuario solo accede a los suyos |
| Contraseña | Autenticación | Mientras exista la cuenta | Hash Argon2id; nunca texto claro |
| Secreto TOTP MFA | MFA | Mientras exista la cuenta | Cifrado AES-256-GCM |
| Caché de reputación | Respetar límite de VirusTotal | 24 horas | Solo hash y veredicto; sin contenido ni vínculo con el usuario |

## Porcentajes

OBJ-01 a OBJ-07: 0% verificado en el repositorio local revisado. Esto expresa ausencia de evidencia implementada aquí; no es una evaluación de trabajo externo al directorio.
