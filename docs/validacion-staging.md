# Validar MetaGuard antes de producción

Esta comprobación se ejecuta en una VM Linux descartable, con datos sintéticos y sin proveedores externos. **No habilita producción ni acredita cumplimiento legal.** Hasta completar los datos del responsable y revisar el [aviso de privacidad](aviso-de-privacidad.md), no se deben usar datos reales.

## Condiciones para ejecutar la prueba

1. Usa un Linux local o un entorno de staging autorizado e independiente. Necesitas una **imagen aprobada del procesador**, ya cargada y fijada por digest. No uses una etiqueta mutable ni permitas que el supervisor construya o descargue imágenes.
2. Prepara una instancia PostgreSQL vacía para staging, con un usuario y secretos exclusivos. Sigue la [guía local](desarrollo-local.md) para las llaves, el origen HTTPS exacto y la inicialización. Aplica `alembic upgrade head` solo al destino descartable y verifica `alembic current`.
3. Levanta el [servicio aislado](procesamiento-archivos.md#run-the-private-listener-on-linux) y la API con UID distintos, sin acceso del proceso de la API al socket de Docker. Configura TLS y cookies seguras. Mantén VirusTotal desactivado y usa un capturador de correo sin relay si necesitas registrar nuevas cuentas.

## Qué debe pasar

| Prueba | Evidencia esperada |
|---|---|
| Cuenta y MFA | Registro sintético, verificación e inicio de sesión. El alta exige probar el autenticador. La recuperación con contraseña y un código de respaldo instala un nuevo autenticador; el dispositivo y las sesiones anteriores dejan de funcionar. |
| Archivo y reporte | Para cada formato JPG, PNG y PDF, sube un archivo sintético con metadatos conocidos. Consulta el reporte; descarga la copia una sola vez y verifica la ausencia de esos metadatos con una herramienta independiente. Un segundo usuario no puede consultar, descargar ni borrar el reporte. |
| Fallos y aislamiento | Confirma en Linux que el parser corre como usuario sin privilegios, sin red, con raíz de solo lectura y con límites de CPU, memoria y tiempo. Si el procesador no responde o la limpieza del contenedor no se puede confirmar, la API no procesa el archivo por su cuenta. |
| Retención y operación | Comprueba el vencimiento y la purga del archivo temporal y del reporte. Ensaya un respaldo y su restauración en otra base descartable. Los logs no deben contener llaves, códigos de autenticación, tokens de descarga ni datos del archivo. |

Registra el commit, el digest de la imagen, la versión del esquema y el resultado observado de cada prueba. Si no hay imagen aprobada o no se puede inspeccionar el aislamiento, marca la prueba de archivos **bloqueada**, no aprobada.

## Composición privada de la API

La fábrica `metaguard_api.staging_runtime:create_staging_app` habilita sesiones y procesamiento solo para un entorno privado con datos sintéticos. No cambia la demo local ni el punto de entrada habitual. No ejecuta migraciones, no aprovisiona cuentas y no publica el frontend.

| Ajuste | Valor para staging |
|---|---|
| `METAGUARD_ENVIRONMENT`, `METAGUARD_STAGING_SYNTHETIC_ONLY` | `production` y `true`. |
| `METAGUARD_AUTH_ALLOWED_ORIGINS` | Lista JSON con un solo origen HTTPS exacto, sin ruta. |
| `METAGUARD_STAGING_ALLOWED_PEER` | IP privada RFC 1918 exacta del proxy inmediato. Usa `127.0.0.1` solo para un proxy HTTPS en el mismo host. |
| `METAGUARD_DB_HOST`, `METAGUARD_DB_PORT`, `METAGUARD_DB_NAME`, `METAGUARD_DB_USER` | IP privada RFC 1918 de PostgreSQL y su puerto, base `metaguard_staging`, rol no administrador `metaguard_app`. No establezcas `PGHOSTADDR`, `PGSERVICE`, `PGSERVICEFILE` ni `PGOPTIONS`. |
| `METAGUARD_STAGING_DB_TLS_CA` | Ruta absoluta a un archivo de CA confiable, protegido y legible por la API. `verify-full` requiere que el certificado del servidor coincida con la IP privada configurada. |
| `METAGUARD_STAGING_PROCESSOR_SOCKET`, `METAGUARD_STAGING_PROCESSOR_UID` | Ruta absoluta del socket Unix y UID real del supervisor. El proceso API corre en Linux con otro UID sin privilegios ni acceso a Docker. |
| `METAGUARD_SECRET_DIR`, `METAGUARD_DB_SECRET_DIR` | Directorios protegidos para las llaves de aplicación y `postgres_password`, respectivamente. Usa credenciales propias del entorno; no copies secretos existentes. |

1. Antes de iniciar, verifica el acceso privado entre hosts, los controles de entrada, la CA, el esquema migrado y el [servicio aislado](procesamiento-archivos.md#run-the-private-listener-on-linux). No abras puertos públicos para probar conectividad. Si falta un control, marca esa parte **bloqueada**.
2. Desde `backend/`, con dependencias fijadas ya disponibles y `STAGING_API_BIND` configurada a la IP privada de la API (o `127.0.0.1` detrás del proxy local), inicia una sola instancia:

   ```sh
   uv run --offline --no-sync uvicorn metaguard_api.staging_runtime:create_staging_app \
     --factory --host "$STAGING_API_BIND" --port 8000 --workers 1 \
     --no-proxy-headers --no-access-log
   ```

   El proxy debe eliminar `Forwarded` y las cabeceras `X-Forwarded-*` de IP, host, puerto y esquema. La API rechaza esas cabeceras y autoriza solo el par directo. Los límites y archivos temporales en memoria no se comparten entre procesos.
3. Usa una cuenta sintética ya verificada en la base dedicada: registro, cambio y restablecimiento de contraseña, verificación adicional por correo, alertas y consultas en línea de HIBP y VirusTotal no están habilitados en esta composición. Prueba sesión, carga, procesamiento aislado y descarga con archivos sintéticos. `/health/ready` solo comprueba una consulta a la base y no acredita el recorrido completo.

Las lecturas GET protegidas de reportes y actividad conservan las comprobaciones de origen y CSRF. Antes de usar un navegador, comprueba que el proxy HTTPS preserve la información necesaria para esas lecturas de mismo origen; la adaptación del proxy de desarrollo de Vite no se aplica en AWS.

La fábrica no acredita conectividad, TLS, permisos de los hosts, imagen aprobada ni un frontend servido. Registra esas pruebas por separado antes de declarar staging operativo. No uses datos reales.

### Ensayo privado en EC2

En dos instancias separadas, la API y PostgreSQL se comunicaron por TCP privado con TLS 1.3 y `verify-full`. El rol de aplicación no era administrador. La base no abrió un puerto público: la regla de red se limitó al backend y un filtro del host permitió solo su IP privada para ese puerto. Desde la instancia del frontend, la conexión a PostgreSQL no se estableció. El listener TCP de PostgreSQL se inició con argumentos manuales; la configuración persistente conserva solo el socket Unix.

Con la API escuchando temporalmente por HTTPS en loopback y el procesador Docker comunicado por socket Unix con UIDs distintos, se verificaron el acceso, la carga de un PNG sintético, su análisis, el reporte, la descarga y el rechazo de una segunda descarga (`404`). La copia perdió el metadato de autor sembrado y conservó los píxeles. Al terminar se retiró la cuenta de prueba y se apagaron la API de ensayo y el supervisor temporal. Este recorrido no verificó el frontend, el proxy público, Gmail ni VirusTotal en vivo.

### Servicios persistentes de staging

- **Base:** `metaguard-staging-db.service` depende de `metaguard-staging-db-guard.service`. La guardia comprueba o instala solo la tabla de staging y PostgreSQL vuelve a validarla en cada arranque. Si la regla, el origen privado, el certificado o el HBA no coinciden con los previstos, no arranca por TCP. No activa ni modifica el firewall general. El clúster estándar sigue en modo manual con configuración de socket Unix.
- **Backend:** `metaguard-staging-api.service` depende de `metaguard-staging-processor.service`. El supervisor autentica al UID de la API por socket Unix y solo él tiene acceso a Docker. La API escucha en `127.0.0.1:8443` por HTTPS; no se abrió un puerto de API o Docker al exterior. Se repitió el recorrido con una cuenta y un PNG sintéticos y se retiró la cuenta después.
- PostgreSQL y la API quedaron habilitados para el próximo arranque; no se reiniciaron las instancias. Los certificados son temporales: el de PostgreSQL vence el **30 de noviembre de 2026 UTC** y el de la API el **7 de diciembre de 2026 UTC**. Renueva y verifica cada certificado de servidor antes de su vencimiento. Si cambia una CA, actualiza el ancla de confianza de los clientes; no desactives la verificación.

Con autorización explícita se compiló el frontend una vez en una copia aislada. Se verificaron las 87 pruebas frontend y los hashes del código fuente y los tres archivos estáticos. La EC2 del frontend sirve una vista previa separada de Nginx por HTTPS en `127.0.0.1:8443`; se comprobaron `/`, `/security/events`, JavaScript y CSS. Antes de instalar el proxy, `/v1` respondía `503` en vez de simular un resultado. Los servicios privados no habilitan registros reales ni justifican publicar la plataforma.

### Integración HTTPS privada del frontend

Después de confirmar la regla TCP/8000 desde el grupo del frontend, se conectaron las tres EC2 sin publicar el sitio. Nginx sigue en loopback y habla con la API mediante TLS verificado en la IP privada del backend. La regla del host restringe esa escucha a la IP privada del frontend. El certificado del upstream vence el **30 de noviembre de 2026 UTC**; el certificado de la vista privada del frontend es independiente. Nginx no agrega IP de cliente y conserva `Cache-Control: no-store`.

El módulo [`deploy/staging/origin.mjs`](../deploy/staging/origin.mjs) distingue un `Origin` ausente de uno presente pero vacío mediante njs. Solo lo completa para los GET de reportes e historial con los requisitos documentados de origen y CSRF, sin reemplazar la decisión del servidor. El [fragmento del proxy](../deploy/staging/upstream.nginx.conf) verifica TLS y elimina las cabeceras de reenvío conocidas. Con un cliente HTTPS y datos sintéticos se verificaron acceso, análisis, reporte, descarga, cierre de sesión y rechazo de reutilización (`404`), origen vacío o duplicado, origen ajeno y CSRF inválido (`403`). El frontend público y los proveedores en vivo siguen fuera de este ensayo.

En Edge aislado, `Referrer-Policy: no-referrer` omitía el requisito de misma procedencia de las lecturas protegidas. El proxy ahora usa `Referrer-Policy: same-origin`: permite `Referer` dentro del mismo origen, pero no lo envía a otros sitios. Se repitió la prueba en navegador sobre un túnel SSH temporal: login y listado `200`, carga `201`, análisis `200`, descarga de un PNG sin autor y con píxeles idénticos, e historial `200` sin `Origin` enviado por el navegador. Se borró la cuenta sintética y se cerró el túnel. El servicio Nginx privado se vinculó al arranque de la instancia; no se abrió un puerto público ni se reinició la EC2.

### Frontend público y entorno funcional privado

El origen `https://metaguard.duckdns.org` tiene un certificado de Let's Encrypt verificado. Sirve los mismos archivos compilados de MetaGuard que la vista privada, con su navegación y sus interacciones visuales. La entrada pública no tiene un proxy a la aplicación: `/v1` y `/health` devuelven `404`, y las escrituras no se aceptan. Los flujos con cuentas sintéticas siguen en el listener privado de staging. El puerto 80 solo responde a las pruebas de control del dominio. Se verificó una renovación simulada y la recarga de Nginx para ese certificado. El [aviso de privacidad](aviso-de-privacidad.md) y el arranque para uso real siguen pendientes.

La [configuración HTTPS pública](../deploy/public/nginx.conf) debe renderizarse con la IPv4 privada de la EC2 del frontend en `__FRONTEND_PRIVATE_IPV4__`, antes de ejecutar `nginx -t`. La lista de rutas de recursos debe coincidir con el manifiesto de la revisión compilada. El [fragmento de staging](../deploy/staging/upstream.nginx.conf) usa `__BACKEND_PRIVATE_IPV4__` y no debe incluirse en el servidor público. Mantén separadas la entrada pública y la de la demo operativa; no abras directamente ni el backend ni PostgreSQL. Para acceso desde otras redes, revisa únicamente la regla HTTPS `443` del grupo del frontend.

## Estado observado

Se construyó la imagen del procesador en el Docker local de Ubuntu/WSL2 con una excepción de build limitada a ese Dockerfile. La etiqueta local es `metaguard-processor:local-02009ea-20261119`. Usa la referencia inmutable `metaguard-processor@sha256:89c698183d363cb7a696ac44a8e43cb6f2194ef9cad95e37b9994ab475db4ab6` en ese daemon. No es una imagen publicada.

El procesador eliminó metadatos sintéticos de PNG, JPG y PDF en contenedores sin red, con raíz de solo lectura y UID sin privilegios. Una segunda prueba conectó las rutas reales de la API a esos contenedores mediante un adaptador de pruebas: pasó la carga, el análisis, el listado y detalle del reporte, el rechazo a otra cuenta, la descarga de un solo uso y el borrado. Usó una base SQLite en memoria y no contactó VirusTotal.

La prueba inicial no verificó el socket Unix nativo. El ensayo separado de abajo cubre esa frontera; queda por comprobar la API y el punto de entrada de staging de extremo a extremo (TLS, límites, registros, retención y restauración del entorno objetivo).

## Privacidad del despliegue

Antes de usar datos reales, comprueba con cuentas y archivos sintéticos:

- En el navegador, la descarga usa `POST /v1/downloads`. El permiso de un solo uso viaja en el cuerpo, no en la URL. Configura el proxy, el servidor y la telemetría para **no registrar cuerpos, cabeceras de autorización, cookies ni respuestas privadas**. Revisa los registros del recorrido sintético, incluidos los errores. No uses secretos reales como marcadores.
- Desde dos pestañas del mismo origen, abre un reporte y cierra sesión desde la otra. La primera debe dejar de mostrar los datos anteriores. Repite el recorrido con el botón Atrás del navegador. Una respuesta pública de registro idéntica para un correo nuevo y otro ya registrado no garantiza que el tiempo del envío de correo sea idéntico.
- Verifica las cabeceras TLS y de seguridad **en la respuesta del host que sirve el HTML**, y la ausencia de caché compartida en las respuestas privadas. No publiques el servidor de desarrollo. El entorno local depende del referente del mismo origen para las lecturas de reportes; comprueba la política efectiva en el navegador.

### Ensayo local con la interfaz actual

El 20 de noviembre de 2026 se aplicaron las migraciones hasta `0011_mfa_recovery_codes` en PostgreSQL descartable. A través del frontend HTTPS local se verificaron el registro con correo capturado, la respuesta idéntica al repetir el registro, el inicio de sesión, la carga de un PNG sintético, la eliminación de sus metadatos, el acceso exclusivo al reporte, la descarga de un solo uso por POST y el borrado. Se usó el procesador en Docker mediante un adaptador de WSL, no la conexión Unix de staging. No se consultaron servicios externos.

Además, pasaron las 6 pruebas optativas de PostgreSQL. Siguen pendientes el entorno de staging separado, la revisión de cabeceras y logs de producción, y la prueba de recuperación de respaldos antes de usar datos reales.

### Evidencia local: socket Unix nativo

El 21 de noviembre de 2026 se probó el código del árbol de trabajo sobre `02009eaf9416` en Ubuntu/WSL2, sin adaptador. Se inició el [servicio privado](procesamiento-archivos.md#run-the-private-listener-on-linux) como UID `42000`, con el cliente nativo como UID `42001` y grupo IPC `43000`. El directorio del socket era `2750` y el socket, `0660`. Se probaron un cliente con UID incorrecto pero con el grupo correcto y un cliente que esperaba un UID de servidor incorrecto; ambas operaciones se rechazaron. El UID del cliente recibió `EACCES` del kernel al acceder a Docker.

En la operación correcta, un PNG sintético llegó por el socket al procesador Docker local fijado al digest `sha256:89c698183d363cb7a696ac44a8e43cb6f2194ef9cad95e37b9994ab475db4ab6`. Una lectura independiente confirmó que desaparecieron los metadatos de prueba y que se conservaron los píxeles. Los eventos de Docker mostraron una única creación, arranque, fin y eliminación; al recibir `SIGTERM` el servicio salió con código `0` y retiró su socket. No se construyó ni se descargó una imagen.

Esta prueba cubrió `ProcessingClient` → socket real → listener → worker, no la ruta HTTP de archivos ni el proxy. El entorno no tenía las dependencias del API Linux ni un proxy de staging configurado. El contenedor duró demasiado poco para capturar nuevamente toda su configuración efectiva de recursos; no se acredita esa inspección en este ensayo.

### Disponibilidad: qué cubre cada límite

| Control | Evidencia exigida |
|---|---|
| Capacidad de análisis | Con dos solicitudes de prueba y un único cupo, la segunda recibe `503` y `Retry-After` sin leer el archivo. El cupo se recupera tras éxito, error o cancelación de la etapa activa. |
| Entrada pública | El origen de la API no está expuesto directamente. El proxy aplica límites de conexiones y tamaño, tiempos de lectura y una cuota agregada entre réplicas. Verifica su configuración y sus respuestas con un entorno descartable. |
| TLS, registros y caché | Las respuestas privadas no se guardan en cachés compartidas. El proxy y la telemetría no almacenan cuerpos, cookies, códigos ni credenciales. Valida el punto de entrada que recibirán los usuarios. |

El límite de la aplicación solo cubre el trabajo admitido en un proceso. La protección contra saturación distribuida o del enlace de red depende del proveedor de entrada; no se validó en la demo ni se generó tráfico de ataque.

### Evidencia local: límites, cabeceras y registros

El frontend de desarrollo y la API escuchaban solo en loopback. Con el certificado local validado, el HTML respondió `200` y el estado de autenticación respondió `200` con `Cache-Control: no-store` y cookies `Secure` y `HttpOnly`. El HTML de Vite no tenía CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` ni `Permissions-Policy`; ese servidor no es un proxy de producción ni se verificaron límites perimetrales en él.

La API local arrancó con los registros de acceso de Uvicorn desactivados. Las pruebas en memoria confirman que los errores de descarga no reflejan ni registran su contenido sintético, pero no verifican los registros de un proxy o recolector externo. Pasaron 69 pruebas de backend sobre límites, archivos, reportes, aislamiento y VirusTotal simulado, y 5 del proxy de desarrollo. No se ejecutó una prueba de carga ni se contactó a VirusTotal.

Para validar la entrada de staging, registrar en el expediente el dominio de prueba, la revisión del proxy y qué red de pares está autorizada a entregar la dirección del cliente. Comprobar que el origen de la API no es accesible directamente, y que el proxy elimina o reemplaza las cabeceras de reenvío del cliente. Probar con dos direcciones sintéticas legítimas que el bloqueo queda circunscrito al par correspondiente. Comprobar por separado que el proxy no registra cuerpos durante el registro, el restablecimiento de contraseña, la confirmación por correo ni la descarga. No habilitar la protección basada en direcciones para usuarios reales si la procedencia de esa dirección no está comprobada.

### Evidencia local: restauración de respaldo

En una instancia separada de PostgreSQL 17.6 y con datos exclusivamente sintéticos, se migró hasta `0011_mfa_recovery_codes`, se creó un respaldo en formato personalizado con `pg_dump` y se restauró en una base vacía con `pg_restore --exit-on-error --single-transaction`. Coincidieron los conteos y las huellas de contenido de 12 tablas, 51 columnas y 22 índices. Se comprobaron también restricciones de unicidad, comprobación, claves foráneas y borrado en cascada. Una restricción de veredicto se representó de manera diferente tras la restauración, pero aceptó los mismos valores permitidos y rechazó el valor inválido en ambas bases.

El 21 de noviembre de 2026 se repitió el ensayo en PostgreSQL 17.6 de loopback con la migración `0012_password_reset`. `alembic check` no detectó cambios pendientes. Se restauraron 13 tablas en una segunda base vacía de la misma instancia descartable. Coincidieron la revisión, la cuenta y el registro de huellas sintéticos. Al borrar la cuenta restaurada se eliminó su registro de restablecimiento por cascada y el origen permaneció intacto. Se detuvo y retiró la instancia descartable.

Se repitió luego con `0016_login_email_challenge`: se restauraron 19 tablas en otra base vacía del clúster de prueba. Coincidieron cinco filas sintéticas: cuenta, evento, estado de intentos, desafío por correo y cola de alertas. Los borrados por cascada afectaron solo el destino. No se inició el despachador ni se enviaron mensajes desde la restauración. Antes de abrir un entorno restaurado para personas reales, verificar que los desafíos, sesiones y entregas restauradas no recuperen autorización por el solo hecho de volver a estar en la base.

No se leyó ni modificó la base en ejecución de la demo. Estos ensayos no acreditan la política de respaldos de producción: allí falta verificar almacenamiento protegido, periodicidad, retención, acceso y restauración en otro entorno.

### Corte U2: comprobaciones locales del 23 de noviembre de 2026

- **PostgreSQL 17.6:** seis pruebas optativas aprobadas en un clúster nuevo de loopback con migración `0016_login_email_challenge`. Se restauró un respaldo sintético en otra base vacía. Coincidieron los inventarios de 19 tablas y las huellas de contenido de cuatro filas. Se compararon 76 restricciones: dos expresiones quedaron escritas con conversiones distintas, pero aceptaron y rechazaron los mismos valores de prueba. El borrado en cascada afectó a la base restaurada y no al origen.
- **Cuentas y proxy:** pasaron 51 pruebas enfocadas de API y cuatro de lógica de origen. El recorrido de registro, reenvío, verificación e inicio de sesión usó datos sintéticos; el ensayo SMTP comprobó el mensaje de alerta en un capturador local sin reenvío. Ninguno verifica entrega real, acceso público o límites del Nginx desplegado.
- **Trabajador:** una prueba que importa solo las fuentes declaradas en el Dockerfile detectó la ausencia del lector de destinos PDF. Tras añadirlo, pasaron 52 pruebas del supervisor y el protocolo IPC. No se construyó una imagen, no se cambió el digest publicado y no se usaron credenciales de AWS.
