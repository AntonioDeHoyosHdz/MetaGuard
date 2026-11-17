# Arquitectura propuesta de MetaGuard

**Propósito:** fijar los componentes y límites de confianza que debe demostrar OBJ-01. **Estado:** diseño propuesto; no implementado.

## Contenido

```mermaid
flowchart LR
  subgraph T1["TB-1 · Dispositivo y red del usuario — no confiables"]
    Browser[ Navegador ]
  end
  subgraph T2["TB-2 · Borde controlado por MetaGuard"]
    Nginx[Nginx · TLS, tamaño y tasa]
  end
  subgraph T3["TB-3 · Red de aplicación — API con red"]
    API[FastAPI · auth, autorización, cifrado, orquestación]
    DB[(PostgreSQL · datos cifrados donde aplica)]
    Secrets[Fuente de secretos · decisión pendiente]
  end
  subgraph T4["TB-4 · Sandbox de procesamiento — sin red"]
    Worker[Procesador · sin privilegios, FS solo lectura]
    Tools[ExifTool + qpdf · verificadores]
  end
  subgraph T5["TB-5 · Terceros — reciben datos mínimos"]
    HIBP[HIBP · prefijo SHA-1 con padding]
    VT[VirusTotal · solo SHA-256, con consentimiento]
    SMTP[SMTP · alertas]
  end
  Browser -->|HTTPS| Nginx
  Nginx -->|cabeceras de proxy saneadas| API
  API <-->|datos y reportes| DB
  API -.->|IPC local por definir; no red del worker| Worker
  Worker --> Tools
  Worker -.->|copia limpia + resultado| API
  API -->|consulta mínima de contraseña| HIBP
  API -->|solo hashes y solo con permiso| VT
  API -->|alertas sin archivos ni metadatos| SMTP
  Secrets -.-> API
```

## Decisiones y límites

| Componente | Responsabilidad / límite |
|---|---|
| Navegador | Interfaz y carga. Archivo, URL, nombre y cabeceras del cliente son datos no confiables. |
| Nginx | TLS, límite de cuerpo y tasa. Descarta cabeceras IP aportadas por el cliente y establece una IP de origen confiable según la topología desplegada. |
| API | Autenticación, CSRF, autorización por objeto, validación de solicitud, SHA-256 sin interpretar el archivo, persistencia cifrada y coordinación. No parsea el formato. |
| Procesador | `ProcessingSupervisor` fija imagen, comando y opciones Docker; entrega solo bytes y MIME mediante stdin al worker privado. El worker reutiliza `process_file`; el contenedor corre sin red ni privilegios, con raíz de solo lectura y límites de recursos. Ve el archivo en claro mientras lo procesa. |
| PostgreSQL | Usuarios, reportes, eventos y caché con sus retenciones. No debe recibir archivos binarios ni valores sensibles en claro cuando la propuesta exige cifrado por campo. |
| Servicios externos | HIBP recibe solo prefijo SHA-1 y padding; VirusTotal recibe hashes SHA-256 únicamente con consentimiento por archivo; SMTP no recibe archivos. |

La propuesta define al operador como confiable, pero no como incapaz de ver el archivo: el servidor lo procesa en claro durante unos segundos. El contrato privado supervisor–worker ya limita el mensaje a bytes y MIME, pero su cableado con API, el transporte API–procesador y la fuente de llaves siguen **PENDIENTES**. El procesador no debe tener ruta de red hacia la API ni Internet; el IPC local debe respetar esa propiedad.

## Qué pasa si falta

Sin límites de confianza y separación comprobable, un archivo hostil podría alcanzar componentes con red o datos persistentes y la promesa de aislamiento no se podría evaluar. La figura no prueba que el despliegue real respete los límites.

## Verificación planificada

El código configura `--network=none`, `--read-only`, usuario no-root, capacidades vacías, `no-new-privileges`, 1 GiB/1 vCPU, 60 s, 64 MiB de `/tmp` y limpieza por nombre de contenedor. La ejecución de Docker, el comportamiento de la imagen construida y la verificación efectiva del aislamiento siguen **PENDIENTES**; esta unidad no conecta la API ni demuestra el despliegue.
