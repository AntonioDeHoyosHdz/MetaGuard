# Aviso de privacidad de MetaGuard — borrador académico

> **Demostración local: usa solo cuentas y archivos sintéticos.** No ingreses datos personales reales ni archivos de otras personas. Este documento es un borrador de trabajo: no está aprobado, no está publicado y no acredita cumplimiento legal.

## Aviso simplificado — borrador para registro y carga

**Responsable y domicilio:** PENDIENTE. **Canal de privacidad:** PENDIENTE.

MetaGuard usa tu correo para crear y verificar la cuenta, y datos de autenticación para iniciar y proteger tu sesión. Si subes un JPG, PNG o PDF, lo procesa para generar una copia limpia y un reporte. El reporte no guarda valores extraídos como coordenadas, autor, número de serie o enlaces. Los archivos pueden contener datos personales, incluidos datos sensibles. Su clasificación para un uso real está pendiente; no subas archivos reales a la demo.

Si la consulta de reputación está habilitada, puedes dejarla sin marcar y usar la limpieza de todas formas. Si decides activarla para un archivo, MetaGuard puede enviar a VirusTotal las huellas SHA-256 del original y de la copia limpia, nunca sus bytes. Los medios generales para limitar el uso o divulgación de datos y solicitar atención de privacidad están **PENDIENTES**. Consulta el [aviso integral — borrador](#aviso-integral).

## Aviso integral

**Identidad del responsable, domicilio y canal de contacto:** PENDIENTE. El equipo del proyecto debe confirmar quién decide sobre el tratamiento y bajo qué marco opera. La participación de una institución en la evaluación académica no la convierte automáticamente en responsable.

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

Canal y procedimiento ARCO, medios para limitar el uso o divulgación, revocación del consentimiento cuando corresponda y forma de comunicar cambios al aviso: **PENDIENTE**. No se ofrecen plazos de respuesta ni un contacto provisional. Dejar de autorizar consultas futuras no retira por sí mismo una huella ya enviada a un proveedor.

## Lista de verificación antes de publicar

- [ ] Confirmar quién es el responsable y qué régimen aplica. Si opera un particular, revisar la [LFPDPPP](https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf), en especial los artículos 14–16, 21–31 y, cuando corresponda, 35–36. Solo si una institución pública actúa efectivamente como responsable, determinar si aplica la [LGPDPPSO](https://www.diputados.gob.mx/LeyesBiblio/pdf/LGPDPPSO.pdf) y revisar sus artículos 20–22, así como las disposiciones que correspondan a esa entidad. Ninguno de los marcos se asume automáticamente.
- [ ] Confirmar identidad, domicilio, canal y procedimiento de privacidad; completar el inventario, finalidades, datos sensibles y reglas de consentimiento aplicables. Dejar claro qué finalidades son necesarias y cuáles son optativas.
- [ ] Inventariar proveedores de infraestructura, correo y consultas externas. Verificar destinatarios, ubicaciones, condiciones, contratos y roles; distinguir los encargos de tratamiento de las transferencias cuando corresponda.
- [ ] Probar expiración, purgas, controles de acceso, registros y restauración en un [staging separado](validacion-staging.md) con datos sintéticos. Definir retención, supresión y tratamiento de respaldos, también para cuentas y sesiones.
- [ ] Revisar ambas modalidades, su versión y los medios de cambio con la persona responsable y asesoría competente. Poner la versión aprobada a disposición antes de solicitar datos, con acceso al aviso integral y consentimiento separado para la consulta opcional. Hasta entonces, mantener la demo privada y sintética.

### Decisiones operativas para revisión interna

| Decisión | Punto de partida sin datos reales | Evidencia que falta para aprobarla |
|---|---|---|
| Responsable y solicitudes | La demo no usa un nombre o domicilio provisional ni ofrece un canal particular como si fuera oficial. | Confirmar quién controla el servicio, qué marco le aplica, el domicilio publicable y un canal institucional o dedicado con responsable de atender solicitudes. |
| Proveedores | La demo funciona con correo capturado localmente, lista de contraseñas local y consultas externas desactivadas. | Identificar alojamiento, respaldo y correo transaccional del entorno real. Confirmar finalidad, ubicación, retención, acceso y supresión de cada servicio antes de activarlo. |
| Registros y respaldos | Mantener fuera de los registros cuerpos, cabeceras de autenticación y códigos. Los respaldos del ensayo solo tuvieron datos sintéticos. | Definir y probar plazos y borrado de archivos de respaldo, versiones y copias; identificar quién puede restaurar. Antes de habilitar un entorno restaurado, comprobar que no reactive sesiones revocadas ni datos vencidos o ya eliminados. |
