# Fase 0 — Exploración

Fecha: 30 de octubre de 2026

## Resumen de la fuente de verdad

Se localizó `U2_PropuestaProyecto_MetaGard_243776.pdf` en la raíz y se extrajo todo su texto a `docs/propuesta-u2.txt` desde sus 19 páginas. La propuesta define 7 objetivos, 4 módulos funcionales y sus límites de alcance. La sección 3.2 conserva seis clases de datos: archivos/copia limpia (10 minutos), reporte (24 horas o borrado manual), eventos/IP (30 días), contraseña (vida de cuenta), secreto TOTP (vida de cuenta) y caché de reputación (24 horas). Se describen medidas de retención y protección para cada una en `docs/trazabilidad.md`.

## Estado real por objetivo

| Objetivo | Estado | Porcentaje comprobado | Hallazgo |
|---|---:|---:|---|
| OBJ-01 Arquitectura/STRIDE | No existe | 0% | Sin diagramas, flujo de datos ni matriz STRIDE. |
| OBJ-02 API segura | No existe | 0% | Sin API, OpenAPI, pruebas ni medición de cobertura. |
| OBJ-03 Limpieza/verificación | No existe | 0% | Sin procesador, corpus ni resultados de verificación. |
| OBJ-04 Frontend/seguridad | No existe | 0% | Sin frontend, pruebas de seguridad ni despliegue MetaGuard. |
| OBJ-05 Contraseñas filtradas | No existe | 0% | Sin integración, fallback o captura de tráfico. |
| OBJ-06 PDF activo | No existe | 0% | Sin neutralización, corpus o evidencia qpdf. |
| OBJ-07 Monitoreo/alertas | No existe | 0% | Sin eventos, bloqueo, correo o pruebas de aislamiento. |

Los criterios exactos de éxito están transcritos en `docs/trazabilidad.md`. El 0% significa que no hay evidencia en este directorio; no afirma nada sobre posibles artefactos fuera de él.

## Inventario y contradicciones

- Raíz: propuesta U2, `.codex/` y un checkout independiente `gentle-ai/`; el checkout de Gentle no es una implementación de MetaGuard.
- En la revisión Fase 0, la raíz todavía no era Git (`git status` falló con “fatal: not a git repository”). Después, durante la publicación solicitada por el usuario, se inicializó y subió a GitHub. El checkout `gentle-ai/` es aparte y no es la aplicación.
- Faltan el backend, frontend, procesador aislado, infraestructura, corpus, diseño, documentación de MetaGuard y pruebas descritos en el prompt.
- No se halló implementación que contradiga la propuesta; la falta de artefactos impide comprobar el cumplimiento.

## Entorno verificado

| Herramienta | Resultado observado | Requisito/uso planteado |
|---|---|---|
| Node.js | v24.11.1 | El prompt no fija versión; frontend previsto con React 18/Vite. |
| Python | 3.12.10 | Coincide con Python 3.12 de la propuesta. |
| pip | 25.0.1 | Disponible. |
| Docker | 29.3.1 | Disponible. |
| Docker Compose | v5.1.1 | Disponible. |
| Go | No disponible en PATH | No es requisito de MetaGuard; impide ejecutar desde este shell el código de Gentle. |
| `pdftotext` | No disponible | Se usó pypdf mediante `uv run --with pypdf`; 19 páginas, 28,580 caracteres extraídos. |
| Gentle | Comando `gentle`/`gentle-ai` no disponible en PATH; la carpeta `gentle-ai/` contiene un checkout del código fuente. | No fue posible ejecutar `/gentle:status`, `/gentle:doctor` ni abrir `/gentle:commands` desde este contexto. No se invocaron comandos no verificados. |
| Paquetes PDF/procesamiento | pypdf no estaba instalado en Python global; `uv` lo ejecutó en entorno temporal. Pillow y pikepdf no están instalados globalmente. | Se verificó solo disponibilidad, sin instalar dependencias de MetaGuard. |

## Huecos y preguntas abiertas

1. ¿Cuáles son los límites aprobados para tamaño de archivo, dimensiones de imagen, páginas PDF, peticiones y tiempo máximo de procesamiento? El prompt pide proponer y justificar, dejando la decisión final al usuario; la propuesta no fija números.
2. ¿Qué campos exactos pertenecen a riesgo alto, medio y bajo y cuál es la justificación de cada clasificación? El prompt ofrece ejemplos, pero la propuesta no establece una tabla normativa completa.
3. ¿Cómo se administrarán y rotarán las claves AES-256-GCM y secretos de servicios, y qué procedimiento se seguirá ante filtración? La propuesta nombra cifrado, pero no gestión operacional de claves.
4. ¿Cuál será el flujo concreto de recuperación de cuenta (códigos de respaldo, recuperación por correo, espera y desbloqueo)? No está definido en la propuesta.
5. ¿Qué fechas reales y responsables se asignan a las fases? La propuesta establece el orden de tres fases, no un calendario fechado.
6. ¿Cuál será la composición y el proceso de generación reproducible del corpus? La propuesta exige 20 archivos para OBJ-03 y 10 PDFs activos para OBJ-06; el prompt amplía detalles del corpus, que aún debe concretarse.
7. ¿Cuál es el mecanismo para tener disponibles los comandos Gentle en el entorno de trabajo? La raíz Git ya se creó y publicó después de esta revisión; los comandos slash siguen sin ser accesibles desde este shell.

## Hecho

- Extracción y lectura de la propuesta completas.
- Creado `docs/trazabilidad.md` y la tarea ODD `odd/tasks/metaguard.md`.
- Sin cambios de código ni pruebas de aplicación: no hay aplicación para ejecutar.

## Parcial / pendiente

- Fase 0 del inventario local finalizada. Confirmación del usuario pendiente antes de iniciar Fase 1.
- No se calculan porcentajes de avance positivos porque no hay evidencia funcional.

## Riesgos y bloqueos

- En Fase 0 no había historial Git local; ese riesgo quedó resuelto para los artefactos actuales al crear el repositorio privado y publicar commits.
- Ausencia de decisiones cuantitativas/operativas puede bloquear límites, seguridad de claves, recuperación y cronograma.
- La interfaz de Gentle no estuvo disponible; estado y capacidades de sus comandos no verificados.

## Qué debe poder explicar el equipo

- Que la propuesta U2 prevalece como fuente de requisitos y que no se ha implementado ni verificado ningún objetivo en esta carpeta.
- Qué se conserva, por cuánto tiempo y con qué protección según la sección 3.2.
- Por qué el repositorio Gentle presente no es el código de MetaGuard y por qué el 0% reportado es una limitación de evidencia local.

