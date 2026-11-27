# Aviso de privacidad de MetaGuard — borrador académico

> **Demostración local: usa solo cuentas y archivos sintéticos.** No ingreses datos personales reales ni archivos de otras personas. Este documento es un borrador de trabajo: no está aprobado, no está publicado y no acredita cumplimiento legal.

## Aviso simplificado — borrador para registro y carga

**Responsable:** Luis Emilio Jaras Sanchez. **Domicilio:** 4a Calle Norte Poniente, Último Suspiro, C. P. 21950. **Correo de contacto para consultas de privacidad:** [jarassanchezl@gmail.com](mailto:jarassanchezl@gmail.com).

MetaGuard usa tu correo para crear y verificar la cuenta, y datos de autenticación para iniciar y proteger tu sesión. Si subes un JPG, PNG o PDF, lo procesa para generar una copia limpia y un reporte. El reporte no guarda valores extraídos como coordenadas, autor, número de serie o enlaces. Los archivos pueden contener datos personales, incluidos datos sensibles. Su clasificación para un uso real está pendiente; no subas archivos reales a la demo.

Si seleccionas un JPG o PNG y eliges revelar su punto GPS, el navegador lee y muestra localmente las coordenadas EXIF de esa imagen. Esa vista no las envía ni las guarda. Si más tarde decides subir el original para limpiarlo, sus bytes pueden contener esos metadatos hasta que se procese la copia.

Al terminar el análisis de un PDF, es posible mostrar temporalmente destinos HTTP(S) retirados, como texto sin parámetros ni fragmentos. Las rutas de esas direcciones pueden contener datos privados. MetaGuard no visita los destinos ni los conserva en el historial.

Si la consulta de reputación está habilitada, puedes dejarla sin marcar y usar la limpieza de todas formas. Si decides activarla para un archivo, MetaGuard puede enviar a VirusTotal las huellas SHA-256 del original y de la copia limpia, nunca sus bytes. El [procedimiento de privacidad propuesto](#solicitudes-de-privacidad) explica cómo solicitar acceso, rectificación, cancelación u oposición, limitar el uso o la divulgación de datos y revocar el consentimiento. Consulta el [aviso integral — borrador](#aviso-integral).

## Aviso integral

**Responsable:** Luis Emilio Jaras Sanchez. **Domicilio:** 4a Calle Norte Poniente, Último Suspiro, C. P. 21950. **Correo de contacto para consultas de privacidad:** [jarassanchezl@gmail.com](mailto:jarassanchezl@gmail.com). El marco aplicable sigue pendiente de revisión. La participación de una institución en la evaluación académica no la convierte automáticamente en responsable.

### Qué datos se usan y para qué

| Datos | Finalidad y tratamiento en la demo |
|---|---|
| Correo y códigos de acceso | El correo identifica la cuenta y recibe los códigos de verificación o de restablecimiento de contraseña. En la demo, el código de verificación admite un uso y dura hasta una hora. El código de restablecimiento es distinto, dura 15 minutos y se invalida al cambiar la contraseña. La base conserva las huellas de los códigos, no los códigos originales. Los mensajes son transaccionales, no avisos de actividad de cuenta. |
| Contraseña y autenticador | Se usa la contraseña para acceder y, con la sesión iniciada, para autorizar su cambio. La base conserva un hash Argon2id, no la contraseña. Si activas MFA, la semilla se guarda cifrada. Se guardan las huellas de los códigos de respaldo y si alguno ya se usó para probar un restablecimiento. Restablecer una contraseña olvidada requiere el código de correo y el segundo factor si lo activaste. El correo no permite desactivar ni reemplazar el autenticador. |
| Sesión y controles contra abuso | Se usan cookies del propio sitio para iniciar y mantener la sesión, comprobar el desafío MFA y prevenir solicitudes iniciadas desde otros sitios (CSRF). El navegador las envía por HTTPS y los scripts no pueden leer las cookies; la interfaz sí recibe el token CSRF por separado para autorizar sus solicitudes. La base guarda huellas de los tokens, junto con fechas de creación, caducidad y revocación cuando corresponde. La API usa la dirección de origen que recibe y, según la operación, la identidad de cuenta para aplicar límites locales. |
| Archivos JPG, PNG y PDF | El navegador envía los bytes por HTTPS al proxy local, que los pasa a la API de loopback. El procesador aislado los lee en claro para limpiar metadatos. El original y la copia limpia que conserva la API se cifran en memoria, no en un almacén persistente. Limpiar metadatos no elimina nombres, rostros, texto ni otra información visible dentro del archivo. |
| Reporte y permiso de descarga | El reporte guarda un identificador, el dueño, las fechas, el tipo de archivo, categorías detectadas, medidas o páginas y resultados de verificación o contadores. No conserva los valores de los metadatos extraídos ni los resultados de reputación. La descarga exige la sesión y un permiso de un uso que se guarda como huella. |
| Actividad de seguridad | Se conserva el tipo de evento, la fecha, un identificador interno de cuenta y la ventana utilizada para agrupar intentos repetidos. Solo el titular con sesión activa puede ver el tipo y la fecha. El historial no muestra ni almacena contraseñas, códigos, direcciones IP ni contenido o nombres de archivos. |
| Protección del inicio de sesión y alertas | Si se habilita, un registro distinto usa una huella con llave de la dirección de origen vinculada a la cuenta para distinguir direcciones y limitar intentos. No es un dato anónimo y no se muestra en el historial. La verificación adicional por correo usa un código distinto del de registro o restablecimiento. La cola de alertas conserva el identificador de cuenta y datos de envío mínimos; el mensaje no incluye la dirección IP ni los detalles del evento. |
| Evento de sistema | Se guarda un diagnóstico genérico si no está disponible la comprobación de contraseñas; el evento no incluye correo, contraseña, IP ni identificador de cuenta. Es independiente del historial de cuenta. |

No introduzcas datos sensibles ni datos de terceros en la demo. Antes de cualquier uso real, está **PENDIENTE** identificar las categorías de datos que podrían llegar en los archivos, incluidos los sensibles, y decidir si se admiten y con qué controles.

### Servicios de terceros

- **Correo transaccional:** la demo usa un capturador SMTP local sin reenvío a internet. Si se conecta un proveedor de correo, este puede tratar el destinatario y el mensaje, incluidos los códigos de verificación, restablecimiento o confirmación de inicio de sesión, y los avisos genéricos de seguridad. Contrato, región, retención y rol del proveedor: **PENDIENTE**. No se presenta Gmail como parte de la demo ni se considera validada la entrega real.
- **Comprobación de contraseñas:** si se habilita Have I Been Pwned (HIBP), para registrar, cambiar o restablecer una contraseña se envían únicamente los primeros cinco caracteres del hash SHA-1 y se solicita relleno de respuesta con `Add-Padding`. La comparación se hace localmente. No se envía la contraseña ni la huella completa. La demo no hace esta consulta: usa una lista local.
- **Reputación de archivos:** VirusTotal está desactivado en la demo. Si se configura, requiere tu elección afirmativa para cada archivo y usa solo los SHA-256 del original y de la copia limpia. Una huella puede permitir reconocer el archivo o vincularlo con un registro conocido: no equivale a anonimato. Si abres un enlace a un reporte de VirusTotal, tu navegador contacta ese sitio en una visita aparte; el sitio puede recibir datos de conexión como tu IP. No tener detecciones no demuestra que el archivo sea seguro.

### Cuánto tiempo están disponibles los datos

Los plazos siguientes describen el comportamiento configurado de la demo, no compromisos de retención de producción:

- El original y la copia limpia dejan de estar disponibles como máximo diez minutos después de que se crea cada temporal. La descarga exitosa y el borrado del reporte retiran la copia limpia antes de ese plazo. El permiso de descarga vence a más tardar junto con la copia.
- El reporte deja de estar disponible a las 24 horas y su dueño puede eliminarlo antes. La actividad de la cuenta se muestra durante 30 días; los eventos y el diagnóstico de sistema son elegibles para purga al cumplir ese plazo. La caché de reputación, si se habilita, dura 24 horas y guarda la huella, el veredicto y, cuando se dispone de ellos, fecha y conteos minimizados, sin asociarlos a la cuenta.
- La sesión local caduca a los 15 minutos o deja de autorizar solicitudes nuevas al cerrarla. Los plazos de conservación de los registros de sesión, las cuentas, los registros del entorno y los respaldos son **PENDIENTES** de definir y verificar para un uso real.

Que un dato venza o deje de verse no demuestra su borrado físico. La aplicación puede purgar datos vencidos si está configurada para ello; quedan **PENDIENTES** las pruebas de limpieza y retención en infraestructura real, incluidos logs, copias de seguridad y snapshots. Consulta el [inventario técnico](datos.md) y el [flujo de datos](flujo-de-datos.md).

### Tus controles y derechos

Si se ofrece la consulta de reputación, puedes no marcarla y aun así limpiar el archivo. Dentro de la aplicación, puedes cerrar sesión, eliminar tus reportes y consultar la actividad reciente de seguridad de tu cuenta. No hay baja de cuenta automatizada. Estos controles no sustituyen un medio para ejercer los derechos de acceso, rectificación, cancelación y oposición (ARCO).

#### Solicitudes de privacidad

**Procedimiento propuesto para el servicio público; aún no está en operación.** La persona responsable indicada en este aviso atenderá las solicitudes por el correo de contacto, sin exigir que el titular inicie sesión en MetaGuard.

1. **Envía la solicitud.** Usa el asunto «MetaGuard — Solicitud de privacidad». Incluye tu nombre, un medio para recibir notificaciones y lo que solicitas. Si corresponde, indica el correo asociado a tu cuenta. Describe los datos afectados, salvo para una solicitud de acceso; para una rectificación, indica qué debe corregirse. No envíes contraseñas, códigos, identificaciones ni archivos personales en el primer mensaje.
2. **Recibe un folio y acredita tu identidad.** La persona responsable revisará el buzón cada día hábil, registrará la fecha de recepción y confirmará el folio sin revelar si existe una cuenta. Para tramitar una solicitud ARCO, indicará un medio protegido para acreditar tu identidad o la de tu representante y sus facultades. Para una rectificación, también podrá pedir respaldo de la corrección. El correo remitente, por sí solo, no acredita la identidad. No se divulgarán ni modificarán datos antes de comprobarla.
3. **Recibe la decisión.** La persona responsable comunicará el resultado por el medio indicado y explicará los motivos si la solicitud se rechaza total o parcialmente. Si resulta procedente, aplicará lo resuelto; para una solicitud de acceso, pondrá los datos a disposición por un medio protegido. Si aplica la [LFPDPPP para particulares, artículos 27–33](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf), se atenderán sus plazos: hasta 20 días desde la recepción para comunicar la decisión y, si procede, hasta 15 días desde esa comunicación para ejecutarla. La ampliación solo procederá como lo permite esa ley y se informará al titular.

Usa el mismo canal para pedir que se limite el uso o la divulgación de tus datos, o para revocar el consentimiento cuando corresponda. Para evitar futuras consultas a VirusTotal, deja sin marcar la opción de reputación en cada archivo. Dejar de autorizar consultas futuras no retira por sí mismo una huella ya enviada al proveedor.

#### Cambios al aviso

La versión vigente y su fecha estarán disponibles desde el enlace «Aviso de privacidad» en el registro y el pie del sitio. Cuando cambien las finalidades o las condiciones de tratamiento, se publicará un resumen del cambio en ese enlace y se mostrará un aviso visible al iniciar sesión. Se solicitará un nuevo consentimiento cuando corresponda.

## Lista de verificación antes de publicar

- [ ] Confirmar qué régimen aplica. Si opera un particular, revisar la [LFPDPPP](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf), en especial los artículos 14–16, 21–31 y, cuando corresponda, 35–36. Solo si una institución pública actúa efectivamente como responsable, determinar si aplica la [LGPDPPSO](https://www.diputados.gob.mx/LeyesBiblio/pdf/LGPDPPSO.pdf) y revisar sus artículos 20–22, así como las disposiciones que correspondan a esa entidad. Ninguno de los marcos se asume automáticamente.
- [ ] Verificar que el domicilio esté completo para correspondencia y ensayar una solicitud sintética de principio a fin: acuse, acreditación por un medio protegido, decisión y registro restringido. Definir la retención y eliminación de esos expedientes. Completar el inventario, las finalidades, los datos sensibles y las reglas de consentimiento aplicables. Dejar claro qué finalidades son necesarias y cuáles son optativas.
- [ ] Inventariar proveedores de infraestructura, correo y consultas externas. Verificar destinatarios, ubicaciones, condiciones, contratos y roles; distinguir los encargos de tratamiento de las transferencias cuando corresponda.
- [ ] Probar expiración, purgas, controles de acceso, registros y restauración en un [staging separado](validacion-staging.md) con datos sintéticos. Definir retención, supresión y tratamiento de respaldos, también para cuentas y sesiones.
- [ ] Revisar ambas modalidades y ensayar el mecanismo de comunicación de cambios con la persona responsable y asesoría competente. Poner la versión aprobada a disposición antes de solicitar datos, con acceso al aviso integral y consentimiento separado para la consulta opcional. Hasta entonces, mantener la demo privada y sintética.

### Decisiones operativas para revisión interna

| Decisión | Punto de partida sin datos reales | Evidencia que falta para aprobarla |
|---|---|---|
| Responsable y solicitudes | El borrador identifica al responsable y propone un procedimiento para el correo de contacto. La demo no admite datos reales. | Confirmar el marco aplicable, comprobar que el responsable recibe y atiende las solicitudes y probar la entrega protegida de evidencias y respuestas. |
| Proveedores | La demo funciona con correo capturado localmente, lista de contraseñas local y consultas externas desactivadas. | Identificar alojamiento, respaldo y correo transaccional del entorno real. Confirmar finalidad, ubicación, retención, acceso y supresión de cada servicio antes de activarlo. |
| Registros y respaldos | Mantener fuera de los registros cuerpos, cabeceras de autenticación y códigos. Los respaldos del ensayo solo tuvieron datos sintéticos. | Definir y probar plazos y borrado de archivos de respaldo, versiones y copias; identificar quién puede restaurar. Antes de habilitar un entorno restaurado, comprobar que no reactive sesiones revocadas ni datos vencidos o ya eliminados. |
