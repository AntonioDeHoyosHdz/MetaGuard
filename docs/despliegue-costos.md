# Despliegue de bajo costo: opciones y bloqueos

**Corte de precios:** 16 de noviembre de 2026. Esta comparación orienta una demo de bajo tráfico; no selecciona proveedor ni autoriza crear recursos. Precios en USD, antes de impuestos y cargos variables salvo que se indique lo contrario.

## Recomendación provisional

La menor factura probable es **frontend estático gratuito + una VM autogestionada**, pero no está lista para desplegarse. La VM concentra API, PostgreSQL y supervisor/worker en una sola máquina, reduce servicios facturados y a cambio exige operación, parcheo y backups propios. No se debe montar el socket de Docker dentro de FastAPI: falta definir el IPC con el supervisor y el traspaso efímero de llaves.

## Comparación de costos

| Candidato | Piso observado | Qué no incluye / tradeoff |
|---|---:|---|
| Cloudflare Pages para el frontend | $0/mes en plan Free | Límite publicado de 500 builds/mes. Publicar desde Git dispara un build; no se ejecutó ninguno. |
| Una VM Hetzner en EE. UU. | CPX21: $37.49/mes | Precio base de cómputo sin IPv4 ni impuestos. Una sola falla afecta API y base; backups, parches y monitoreo son responsabilidad del equipo. No se midió si el tamaño alcanza. |
| Servicios separados en Render | Aproximadamente $51/mes: API $7 + worker $25 + PostgreSQL 1 GB $19 | Estimación de compute; sumar almacenamiento, tráfico excedente y cualquier persistencia. El worker requerido y su sandbox todavía no están validados en esta plataforma. |

Render publica un worker de 1 CPU/2 GB a $25/mes y PostgreSQL de 0.5 CPU/1 GB a $19/mes; el plan de base de datos de $6 tiene solo 256 MB y no se usa para estimar la opción prudente. El servicio web de $7 tiene 512 MB. Esta suma no sustituye una prueba de carga ni confirma que Render permita el aislamiento Docker requerido.

**R2 es opcional, no está seleccionado:** el nivel gratuito publica 10 GB-mes, 1 millón de operaciones Clase A, 10 millones Clase B y egreso gratuito. El código aún no tiene un flujo de carga/almacenamiento por API; T3d deberá definir almacenamiento temporal cifrado, retención y purga antes de elegir si hace falta un object store.

## Por qué no usar el nivel gratuito como base real

Render documenta que los servicios web Free duermen tras 15 minutos inactivos, no tienen disco persistente y pueden reiniciarse; workers, cron y discos persistentes requieren compute pagado. Su PostgreSQL Free vence a los 30 días, limita el almacenamiento a 1 GB y no incluye backups. Sirve para experimentar, no para cuentas y datos que deban persistir.

## Bloqueos antes de seleccionar o desplegar

- T2o y T2p siguen sin prueba en PostgreSQL real; la prueba opt-in actual se omite si no se habilita el harness local desechable.
- T3c aún necesita prueba del runtime de contenedor. La instrucción vigente prohíbe builds tras cambios, así que no se construyó ni ejecutó la imagen.
- Faltan el contrato de IPC API–worker y el uso efímero de llaves; no se debe dar autoridad Docker a la API.
- Faltan la recuperación segura de respaldos, el contacto del aviso de privacidad y políticas finales de autenticación/correo.
- No crear servicios ni publicar hasta autorizar proveedor, cuenta, región y operación de despliegue. No se creó infraestructura ni se enviaron archivos.

## Fuentes oficiales consultadas

- [Hetzner: ajuste de precios de junio de 2026](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/) — tabla de EE. UU.; precio sin IPv4.
- [Render: precios](https://render.com/pricing) y [planes de cómputo](https://render.com/docs/compute-plans) — servicios, workers y PostgreSQL.
- [Render: limitaciones del nivel gratuito](https://render.com/docs/free) — suspensión, expiración de PostgreSQL, discos y backups.
- [Cloudflare Pages: precios](https://www.cloudflare.com/en-gb/developer-platform/products/pages/) y [límites](https://developers.cloudflare.com/pages/platform/limits/) — plan Free y builds.
- [Cloudflare R2: precios y cuota gratuita](https://developers.cloudflare.com/r2/pricing/) — almacenamiento, operaciones y egreso.

Los importes cambian y se deben verificar de nuevo antes de contratar. No hubo build, conexión a cuentas de proveedores, creación de infraestructura ni despliegue en esta evaluación.
