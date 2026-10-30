# Fase 3 (seguimiento) — Backend (OBJ-01/02)

Fecha de inicio: 30 de octubre de 2026. Esta es la Fase 3 del seguimiento ODD; la propuesta U2 denomina a OBJ-01/02 como su primer hito base. Rama apilada: `feat/phase3-backend`, sobre la rama de diseño visual; PR todavía no creado.

## Autorización y decisiones

- El usuario aprobó el plan de backend el 30-10-2026.
- El usuario aprobó para demo todos los límites de `docs/limites.md`: 25 MiB por archivo; imagen hasta 8,000 px por lado y 40 MP; PDF hasta 100 páginas; 60 s por archivo; worker de 1 vCPU/1 GiB/1 trabajo activo; tasa general 60/min/IP y 120/min/cuenta; registro 5/h/IP; carga 3/min/IP y 10/h/cuenta; bloqueo progresivo tras 5 fallos del par cuenta+IP por 1, 5 y 15 min. Ninguno está medido ni aprobado para producción.
- El usuario eligió Docker Secrets montados al runtime como fuente de secretos de demo. KMS, rotación productiva y responsables siguen pendientes; el worker no recibe llaves hasta definir y revisar un canal seguro.
- No se retrofechan commits ni se alteran autores/fechas. Los commits serán cortos, básicos y en inglés según la preferencia del usuario.

## Plan de trabajo

| Unidad | Alcance | Evidencia de cierre |
|---|---|---|
| 1. Base del backend | FastAPI, configuración fail-closed, conexión PostgreSQL, modelos y Alembic, pruebas y OpenAPI coherente | Comando de prueba reproducible, migración validada y contrato documentado; no contiene secretos |
| 2. Auth y acceso | Registro/login, cookies seguras, CSRF/Origin, Argon2id, TOTP, autorización por objeto y límites | Pruebas de autenticación/CSRF/BOLA/tasa; revisión independiente de seguridad antes de cerrar |
| 3. Ciclo de archivo | Carga acotada sin parsear en API, hash, descarga de un uso, retención/purga | Pruebas de límite, propiedad, replay/expiración/borrado y restos/logs |
| 4. Proxy y ejecución | Nginx con origen de IP confiable; servicios demo, límites de recursos y secreto montado | Validación de configuración y prueba contra `X-Forwarded-For` falsificado |

La limpieza/neutralización, la integración con el worker y su transferencia de datos/llaves pertenecen a la fase siguiente o requieren una decisión de IPC antes de escribir ese camino. El backend no debe afirmar que un archivo subido quedó limpio.

## Pendientes que no se inventarán

- TTL exacto de JWT/desafío MFA, contrato final de CSRF y parámetros de Argon2id.
- Esquema final de reportes/eventos y campos cifrados; retención y borrado de respaldos.
- Canal API–worker y uso efímero de llave en procesamiento; proveedor/rotación productiva.
- Flujo completo de recuperación (TTL y espera); se pospone para no crear un bypass de MFA.

## Estado inicial

- Backend, OpenAPI ejecutable, migraciones, pruebas y despliegue: **no existen** al comenzar esta fase.
- Las decisiones anteriores quedaron aprobadas; aún no hay controles funcionales verificados.
- OBJ-01/02: 0% de éxito funcional verificado al inicio. Las cifras solo cambiarán con evidencia de ejecución real.
