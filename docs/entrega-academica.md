# Presentar MetaGuard y reunir evidencia para U2

La entrega muestra un prototipo local con cuentas, MFA y procesamiento aislado de archivos sintéticos. No es un despliegue público ni certifica la seguridad o la conformidad legal del producto.

## Preparar la demo

1. Abre un checkout conocido y anota su revisión con `git rev-parse --short HEAD` y si hay cambios locales con `git status --short`. Comprueba los requisitos en la [guía local](desarrollo-local.md).
2. Usa PostgreSQL descartable, HTTPS de loopback, un capturador SMTP sin relay y una lista local de contraseñas bloqueadas. Aplica las migraciones antes de iniciar la API y anota la salida de `alembic current`. Gmail, HIBP en línea y VirusTotal quedan fuera de la demo.
3. Para mostrar archivos en vivo, comprueba antes de la presentación el [servicio privado en Linux](procesamiento-archivos.md#run-the-private-listener-on-linux), con UID de API y procesador distintos y una imagen aprobada ya disponible por digest. La API no debe acceder al socket de Docker. Si no está disponible, muestra cuentas y MFA en vivo y presenta el [ensayo de archivos ya registrado](validacion-staging.md#ensayo-local-con-la-interfaz-actual) como evidencia previa. No reemplaces el procesador aislado con un parser dentro de la API.

### Crear una muestra sintética

Desde la carpeta `backend/`, en PowerShell, crea un PNG pequeño con un campo `Author` ficticio. El comando solo usa Pillow ya instalado. Guarda la carpeta temporal que imprime; no uses archivos personales.

```powershell
@'
from pathlib import Path
from tempfile import mkdtemp
from PIL import Image, PngImagePlugin

path = Path(mkdtemp(prefix="metaguard-demo-")) / "sample.png"
metadata = PngImagePlugin.PngInfo()
metadata.add_text("Author", "Synthetic demo fixture")
Image.new("RGB", (24, 16), "navy").save(path, pnginfo=metadata)
print(path)
'@ | uv run --offline --no-sync python -
```

Si tienes ExifTool disponible localmente, compara `exiftool -PNG:Author <ruta>` sobre el original y la copia limpia. En el original se espera el autor ficticio; en la copia, que no aparezca ese campo. Así no dependes solo de lo que informa el procesador. Esta muestra no sustituye el [corpus U2](corpus-de-pruebas.md).

## Guion de presentación

| Paso | Resultado que debes observar |
|---|---|
| 1. Disponibilidad | La página HTTPS local abre sin advertencia. `/health/live` y `/health/ready` devuelven `200`; esto confirma vida de la API y conectividad a PostgreSQL, no el procesador. |
| 2. Cuenta sintética | Registra una cuenta `@example.test`, usa el código del capturador e inicia sesión. Repetir el registro no debe presentar un estado distinto ni volver a enviar un código. La respuesta del API no contiene el código. En una cuenta aún pendiente, `Solicitar otro código` con la contraseña original permite usar el reemplazo una sola vez; el anterior deja de valer. |
| 3. MFA | Da de alta TOTP y conserva un código de respaldo para el ensayo. Vuelve a iniciar sesión y reemplaza el autenticador con contraseña y código de respaldo. Comprueba que se emiten códigos nuevos, que el anterior ya no se acepta y que puedes iniciar sesión con el autenticador nuevo. Pausa la captura mientras se muestran semillas o códigos. |
| 4. Archivos y reportes | Sube el PNG con VirusTotal sin marcar. Observa la categoría de autor y no su valor. Descarga la copia limpia, comprueba su formato y que se omite el autor, y confirma que la segunda descarga no devuelve el archivo. El dueño puede eliminar el reporte; una segunda cuenta no puede abrirlo. |
| 5. Contraseña | Cambia la contraseña desde la cuenta iniciada y comprueba que se cierran las sesiones. La contraseña anterior falla, la nueva funciona y el autenticador configurado no cambia. |
| 5b. Contraseña olvidada | Cierra sesión y solicita otro código desde **Olvidé mi contraseña** con una cuenta verificada. Tómalo del capturador SMTP sin grabarlo. Verifica que, si la cuenta usa MFA, no basta el código de correo sin el segundo factor. Restablece con ambos, comprueba que no inicia sesión automáticamente y que el código no se puede reutilizar. |
| 6. Cierre | Con un reporte abierto en otra pestaña, cierra la sesión y confirma que los datos anteriores dejan de mostrarse. Muestra solo estados y resultados; no grabes cabeceras, cookies ni cuerpos privados. |
| 7. Actividad de seguridad | Con una cuenta verificada ficticia, realiza un intento con contraseña incorrecta y luego entra válidamente. Abre **Ver actividad de seguridad** y comprueba que muestra el intento y la fecha, sin correo ni IP. Entrar con otra cuenta no debe mostrar el evento. Sal de la sesión y verifica que el panel desaparece. |
| 8. Alertas | Ejecuta la prueba local de [actividad y correo de seguridad](desarrollo-local.md#probar-actividad-y-correo-de-seguridad). El SMTP empieza con un puerto libre en loopback y no reenvía. Registra únicamente el resultado y si el mensaje llegó en menos de un minuto; no muestres destinatarios, credenciales ni códigos en la evidencia. |

Registra por prueba: fecha, revisión (incluidos cambios locales), sistema, versión de esquema, digest del procesador si se utilizó, entrada sintética, resultado esperado y observado. Marca **aprobada**, **fallida**, **no ejecutada** o **bloqueada**. Separa capturas del ensayo de las del día de presentación. Conserva resultados sin contraseñas, códigos, tokens, rutas personales o llaves.

## Trazabilidad U2

Esta tabla resume evidencia registrada hasta el 20 de noviembre de 2026; no convierte una prueba local en aceptación de U2. El [corte de Fase 0](trazabilidad.md) permanece como antecedente.

| Objetivo | Evidencia disponible | Pendiente para acreditar U2 |
|---|---|---|
| OBJ-01 — Arquitectura y amenazas | [Arquitectura](arquitectura.md), [flujo de datos](flujo-de-datos.md) y [STRIDE](stride.md) documentan límites y 14 amenazas con controles y pruebas previstas. | Vincular cada amenaza al resultado de su prueba y al entorno reproducible que la verificó. |
| OBJ-02 — API segura | [Rutas implementadas](api.md) superan el mínimo de 12; el corte del 19 de noviembre registró 88.31 % de cobertura del backend. Hay pruebas de propiedad, revocación, descarga y expiración, y ensayos con PostgreSQL descartable. | Repetir cobertura sobre la revisión entregada; documentar la prueba de IP falsificada en el punto de entrada y la retención/purga del runtime Linux. |
| OBJ-03 — Análisis y limpieza | Pruebas sintéticas de JPG, PNG y PDF; ejecución con contenedores locales y un ensayo de interfaz con PNG, registrados en [staging](validacion-staging.md). El reporte actual muestra categorías, no un antes/después de los valores. | Completar y versionar el corpus U2 de 20 archivos y comprobar independientemente el 100 % de campos de riesgo alto sembrados. |
| OBJ-04 — Frontend y seguridad | Ensayo local HTTPS con registro y reportes, descarga de un uso y controles de propiedad. No incluye mapa GPS autoalojado ni actividad de cuenta. | Cerrar la brecha funcional, completar los escaneos ZAP, pip-audit, npm audit y Trivy sin altos/críticos abiertos, capturar el tráfico del mapa y demostrar el despliegue de un comando. |
| OBJ-05 — Contraseñas filtradas | Transporte HIBP con prefijo y padding bajo pruebas simuladas de registro; respaldo local con evento mínimo. El cambio autenticado de contraseña aplica esa política; la demo no consulta HIBP. | Documentar el resultado 20/20, una captura controlada donde solo sale el prefijo con padding y la evidencia de caída simulada y respaldo. |
| OBJ-06 — PDF activo y reputación | Pruebas sintéticas de neutralización y cliente VirusTotal simulado. Una prueba aislada autorizada sobre el SHA-256 de entrada vacía obtuvo HTTP 200; no verificó el flujo de navegador a proveedor. El reporte conserva un contador de enlaces, no sus valores ni los resultados de reputación. | Las 10 muestras PDF, variantes codificadas/comprimidas, qpdf y evidencia de consulta consentida solo por hash. U2 pide mostrar ambos hashes y sus resultados; la API expone la reputación solo en la respuesta inmediata. |
| OBJ-07 — Monitoreo y alertas | La política habilitada conecta los siete tipos con historial aislado por titular. Pruebas sintéticas cubren bloqueo progresivo del mismo par, independencia de otra dirección y prueba adicional con TOTP o correo. Una alerta de acceso válido desde una dirección nueva llegó al capturador SMTP de loopback en menos de un minuto. | Reproducir con datos sintéticos sobre el punto de entrada separado; confirmar que solo el proxy autorizado suministra la dirección, revisar los registros y verificar la configuración del remitente antes de habilitarlo para usuarios. |

### Evidencia añadida el 21 de noviembre de 2026

- **Corpus:** 20 imágenes, 10 PDF inertes y 20 escenarios de contraseñas con transporte simulado. Las 61 pruebas enfocadas y los 30 SHA-256 se verificaron, incluidas 10 comprobaciones independientes con Poppler. Los [comandos y límites de la prueba](corpus-de-pruebas.md) distinguen lo que falta validar con ExifTool y `qpdf`. Los PDF inertes no demuestran neutralización de contenido ejecutable.
- **Escaneo estático:** [CodeQL 2.27.4](reporte-seguridad-codeql.md#corte-con-historial-y-alertas) informó 0 resultados en 12 archivos JavaScript/TypeScript y 8 en 75 archivos Python del corte con historial y alertas; el resultado nuevo es un HMAC de direcciones por cuenta, no almacenamiento de contraseñas. Se usó una copia de solo código, sin compilar ni publicar el SARIF. `npm audit --offline --audit-level=high --json` informó 0 avisos con los datos locales; no valida la vigencia de la base de avisos. Faltan los escaneos de dependencias Python e imagen y la comprobación pasiva del punto de entrada.
- **Aislamiento:** pasó un PNG sintético a través del [socket Unix nativo con UID separados](validacion-staging.md#evidencia-local-socket-unix-nativo) en Ubuntu/WSL2. Es una prueba del cliente, el servicio y el contenedor; no es un recorrido HTTP por el proxy de staging.

### Evidencia añadida el 23 de noviembre de 2026

| Alcance | Resultado observado | Límite de la evidencia |
|---|---|---|
| Mapa GPS incluido en el frontend | Edge mostró un punto EXIF de una imagen sintética. Seleccionar y revelar la ubicación generó cero solicitudes y el punto desapareció al cerrar sesión. El mapa usa un SVG incluido en lugar de Leaflet y teselas. | Ensayo local de la interfaz con sesión simulada; no prueba la disponibilidad de la versión publicada. |
| Reputación | La respuesta inmediata muestra los dos SHA-256 solo con consentimiento; los avisos distinguen el original de la copia. Pruebas del backend confirmaron que no se agregan al historial. | La captura usa un proveedor simulado. No se consultó VirusTotal en vivo. La app no desinfecta archivos ni garantiza que sean seguros. |
| Verificación independiente del corpus | ExifTool 12.76 confirmó la eliminación de 42 campos examinados en 20 imágenes sintéticas. Las 10 copias PDF inertes pasaron `qpdf 12.4.2 --check`, perdieron los marcadores comprobados y conservaron el render de Poppler. | El original sintético PDF-10 dio un aviso por un árbol de nombres vacío; la copia pasó sin avisos. Las diez muestras son inertes, no acreditan el criterio de diez PDF con contenido activo. |
| Destinos retirados de PDF | El informe inmediato puede mostrar destinos redactados de un PDF sintético. Edge verificó que no eran clicables, que la consulta y el fragmento no aparecían, que el historial no mostraba el destino y que revelarlo no produjo solicitudes. | La captura usa el resultado real del procesador, con transporte y sesión simulados. La imagen fijada anterior no incorpora la lista. |
| Corpus PDF con acciones benignas | Diez muestras de navegación, enlaces, formularios y adjuntos de texto pasaron qpdf 12.4.2. Cuatro tenían objetos comprimidos y una tenía un nombre de destino codificado. La copia y la referencia sin acciones se renderizaron igual en Poppler 26.07.0. | La inspección no ejecutó las acciones ni usó cargas maliciosas. No demuestra detección universal de malware. |
| Disponibilidad del sitio | Edge obtuvo HTTPS 200 para la portada y 403 en la comprobación de sesión, sin credenciales. | Compatible con el ensayo previamente limitado por IP. No acredita registro ni entrada públicos. |

Las capturas y el CSV de resultados por muestra acompañan el anexo académico. No contienen credenciales ni archivos de usuarios.

## Antes de usar datos reales

Quedan pendientes la validación del entorno de staging separado, la revisión del [aviso de privacidad](aviso-de-privacidad.md), cabeceras y registros del punto de entrada, y los controles de retención y restauración operativos. Los ensayos ya registrados con archivos sintéticos no sustituyen esas comprobaciones. El [registro de verificaciones](../odd/tasks/metaguard-completion.md) conserva el historial técnico.
