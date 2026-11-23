# Despliegue de bajo costo: opciones y bloqueos

**Corte de precios:** 16 de noviembre de 2026. Esta comparación orienta una demo de bajo tráfico; no selecciona proveedor ni autoriza crear recursos. Precios en USD, antes de impuestos y cargos variables salvo que se indique lo contrario.

## Recomendación provisional

En el corte de precios, la menor factura estimada era **frontend estático gratuito + una VM autogestionada**, pero la opción no está lista para desplegarse. La VM concentra API, PostgreSQL y supervisor/worker en una máquina; reduce servicios facturados a cambio de operar parches, backups y monitoreo. La API no debe tener acceso a Docker: el [IPC privado Linux](procesamiento-archivos.md#run-the-private-listener-on-linux) está implementado, no transfiere llaves y aún debe verificarse con distintos UID en staging.

## Comparación de costos

| Candidato | Piso observado | Qué no incluye / tradeoff |
|---|---:|---|
| Cloudflare Pages para el frontend | $0/mes en plan Free | Límite publicado de 500 builds/mes. Publicar desde Git dispara un build; no se ejecutó ninguno. |
| Una VM Hetzner en EE. UU. | CPX21: $37.49/mes | Precio base de cómputo sin IPv4 ni impuestos. Una sola falla afecta API y base; backups, parches y monitoreo son responsabilidad del equipo. No se midió si el tamaño alcanza. |
| Servicios separados en Render | Aproximadamente $51/mes: API $7 + worker $25 + PostgreSQL 1 GB $19 | Estimación de compute; sumar almacenamiento, tráfico excedente y cualquier persistencia. El worker requerido y su sandbox todavía no están validados en esta plataforma. |

Render publica un worker de 1 CPU/2 GB a $25/mes y PostgreSQL de 0.5 CPU/1 GB a $19/mes; el plan de base de datos de $6 tiene solo 256 MB y no se usa para estimar la opción prudente. El servicio web de $7 tiene 512 MB. Esta suma no sustituye una prueba de carga ni confirma que Render permita el aislamiento Docker requerido.

**R2 es opcional y no está seleccionado:** en el corte, el nivel gratuito ofrecía 10 GB-mes, un millón de operaciones Clase A, diez millones Clase B y egreso gratuito. La carga y descarga actuales usan [temporales cifrados en memoria](datos.md), con purga por proceso. No incluyas almacenamiento de objetos en la estimación base; requeriría una decisión aparte sobre persistencia y retención.

## Por qué no usar el nivel gratuito como base real

Render documenta que los servicios web Free duermen tras 15 minutos inactivos, no tienen disco persistente y pueden reiniciarse; workers, cron y discos persistentes requieren compute pagado. Su PostgreSQL Free vence a los 30 días, limita el almacenamiento a 1 GB y no incluye backups. Sirve para experimentar, no para cuentas y datos que deban persistir.

## Bloqueos antes de seleccionar o desplegar

- La [evidencia local](validacion-staging.md#estado-observado) incluye PostgreSQL descartable, una restauración sintética y una imagen Docker disponible solo en WSL2. No sustituye la prueba de staging con el socket Unix nativo, permisos efectivos, UID separados y el aislamiento del proveedor elegido.
- Faltan supervisión y alertas operativas, recuperación periódica de respaldos, TLS y registros del punto de entrada, y las políticas finales de autenticación/correo. El [aviso de privacidad](aviso-de-privacidad.md) permanece pendiente de revisión; no usar datos reales.
- No crear servicios ni publicar hasta autorizar proveedor, cuenta, región y operación de despliegue. No se creó infraestructura ni se enviaron archivos.

## Fuentes oficiales consultadas

- [Hetzner: ajuste de precios de junio de 2026](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/) — tabla de EE. UU.; precio sin IPv4.
- [Render: precios](https://render.com/pricing) y [planes de cómputo](https://render.com/docs/compute-plans) — servicios, workers y PostgreSQL.
- [Render: limitaciones del nivel gratuito](https://render.com/docs/free) — suspensión, expiración de PostgreSQL, discos y backups.
- [Cloudflare Pages: precios](https://www.cloudflare.com/en-gb/developer-platform/products/pages/) y [límites](https://developers.cloudflare.com/pages/platform/limits/) — plan Free y builds.
- [Cloudflare R2: precios y cuota gratuita](https://developers.cloudflare.com/r2/pricing/) — almacenamiento, operaciones y egreso.

Los importes corresponden al corte indicado y se deben verificar de nuevo antes de contratar. La evaluación de costos no creó infraestructura ni realizó un despliegue.
