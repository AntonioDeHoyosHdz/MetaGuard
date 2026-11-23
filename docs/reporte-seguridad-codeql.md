# Primera evaluación de seguridad de MetaGuard

## Repetición local — 21 de noviembre de 2026

Se repitió el análisis sobre una copia de solo código del árbol de trabajo basado en `02009ea`, con `codeql database create --build-mode=none` y `codeql database analyze` usando las suites `security-extended` instaladas de CodeQL 2.27.4. No se incluyeron secretos, datos de usuarios, entornos, dependencias instaladas ni pruebas sintéticas como si fueran código de producción.

| Alcance | Resultado |
|---|---|
| 10 archivos fuente del frontend | 0 resultados automáticos. |
| 64 archivos Python del API y de migraciones | 7 resultados automáticos: 3 de hashing, 2 sobre cookies, 1 de logging y 1 de modo de archivo. |

La lectura inicial distingue el SHA-1 de la consulta por rango de HIBP del almacenamiento Argon2id de contraseñas; los otros hashes señalados están en claves de cuotas y códigos de respaldo aleatorios. El resultado de logging apunta a un contador de registros vencidos, no al código de recuperación. La alerta del socket se refiere al modo de grupo `0660`, probado con grupo dedicado y comprobación de UID; no acredita que la configuración operativa de staging sea idéntica.

El seguimiento manual de los dos avisos de cookies distinguió tres flujos: el estado preautenticado solo emite la cookie cuando genera un token nuevo; el desafío existente reusa el valor CSRF después de validar origen, longitud, alfabeto y coincidencia; y el inicio de sesión emite su token firmado y un CSRF aleatorio. La contraseña se usa para comprobar la credencial, no como valor de `Set-Cookie`. En esos flujos revisados no se confirmó escritura de una contraseña ni inyección de una cabecera. Esto no acredita todos los escenarios de cookies del navegador, del proxy o de una futura revisión.

Los siete resultados se contabilizan y no se ocultaron con supresiones. Este primer corte es anterior a los cambios de historial y alertas.

### Corte con historial y alertas

La segunda ejecución examinó 12 archivos JavaScript/TypeScript, incluida la configuración de proxy de desarrollo, y 75 archivos Python de aplicación y migraciones. Informó 0 resultados para la interfaz y 8 para Python. El resultado nuevo corresponde al HMAC-SHA-256 que se usa para representar direcciones por cuenta, no para guardar contraseñas; las contraseñas siguen usando Argon2id. Los otros siete resultados son de los grupos descritos arriba. No se sustituyen los escaneos de dependencias e imagen ni se evalúa el punto de entrada real.

El resto de esta página conserva el informe inicial del 17 de noviembre.

**Fecha:** 17 de noviembre de 2026. **Resultado:** se corrigió una fuga de metadatos privados en PDF reproducida con archivos sintéticos. La consulta propia dejó de señalar la implementación corregida, pero no demuestra que el proyecto esté libre de vulnerabilidades.

## Alcance y método

Se analizó la aplicación web en el estado basado en el commit `35d5443`, con CodeQL CLI 2.27.4, sin compilar la aplicación (`--build-mode=none`). Se preparó una copia del código rastreado, sin entornos virtuales, dependencias instaladas, archivos `.env` ni secretos. La extracción inicial cubrió 71 de 71 archivos Python y 8 de 8 unidades JavaScript/TypeScript identificadas por CodeQL; la copia incluía siete archivos de código JS/TS y archivos de configuración. Se ejecutaron las suites locales `security-extended`: 52 consultas para Python y 105 para JavaScript.

| Análisis inicial | Resultado | Interpretación |
| --- | --- | --- |
| Python | 11 alertas `py/weak-sensitive-data-hashing` | Una corresponde al SHA-1 requerido por el protocolo de rango de contraseñas de HIBP; diez están en pruebas sintéticas. No se trata del almacenamiento de contraseñas. |
| JavaScript/TypeScript | 0 alertas | No garantiza ausencia de vulnerabilidades. |
| Revisión independiente | Fuga de metadatos privados PDF confirmada | No fue detectada por las suites estándar; se reprodujo y corrigió por separado. |

La [API de HIBP](https://haveibeenpwned.com/API/v3#PwnedPasswords) requiere el prefijo de cinco caracteres del SHA-1 para la consulta por rango. No se reemplazó por otro hash porque rompería ese protocolo; esto no justifica usar SHA-1 para almacenar contraseñas.

## Hallazgo corregido: datos privados en `/PieceInfo`

El limpiador podía conservar identificadores privados en diccionarios o flujos PDF `/PieceInfo` y aun así indicar que el archivo se había verificado. La prueba usó únicamente datos sintéticos; no se verificó una vía pública de explotación y actualmente no hay un endpoint público de carga implementado.

La corrección elimina esa entrada en el catálogo, las páginas y el tráiler, informa la categoría `document_info` y comprueba su ausencia. Además, identifica objetos indirectos pertenecientes al subárbol privado y **rechaza** el archivo si todavía son alcanzables desde otra referencia: es preferible rechazar un PDF con recursos compartidos que entregar uno con información privada o dañarlo silenciosamente. El recorrido limita profundidad y cantidad de nodos.

Las pruebas cubren ubicaciones en catálogo, página y tráiler; contenedores directos e indirectos; cadenas y flujos; referencias compartidas a diccionarios, arreglos, cadenas o flujos; recursos de página compartidos y ciclos. Una revisión independiente comprobó los casos de referencias compartidas y de tráiler.

**Límite importante:** la protección de referencias compartidas identifica objetos indirectos, no copias independientes del mismo dato. Otros metadatos propietarios, datos duplicados o información oculta en el contenido pueden persistir. No se puede afirmar que se hayan eliminado todas las variantes posibles ni toda la información sensible de cualquier PDF.

## Consulta compartida y comprobaciones

La consulta propia está en [`security/codeql/python/pdf-pieceinfo-policy.ql`](../security/codeql/python/pdf-pieceinfo-policy.ql), con instrucciones en su [README](../security/codeql/python/README.md). Es una regla estructural específica de esta arquitectura: busca un escáner `_scan_pdf` sin ciertas referencias a la política de `/PieceInfo` o a la protección de alias. **No verifica semánticamente que esas funciones sean correctas**, no cubre todas las bibliotecas PDF y puede pasar por alto implementaciones distintas.

| Consulta propia | Alertas |
| --- | ---: |
| Antes de la corrección | 1 |
| Corrección intermedia sin defensa de alias | 1 |
| Implementación final analizada | 0 |

Las tres ejecuciones de la consulta propia terminaron correctamente. La suite estándar Python se ejecutó antes de la corrección; el intento de volver a ejecutarla después falló porque a la base local de CodeQL le faltaba su archivo de esquema. Por ello no se presenta un resultado posterior de la suite estándar. Los resultados originales y los de la consulta propia se conservaron localmente.

| Verificación | Resultado |
| --- | --- |
| Backend: `uv run --no-sync pytest --no-cov -q -p no:cacheprovider` | 361 aprobadas, 6 omitidas. Las omitidas requieren habilitación explícita y una base PostgreSQL desechable local. |
| Backend: Ruff sobre los archivos modificados | Formato y comprobaciones aprobados. |
| Frontend: `npm test` | 12 pruebas aprobadas en 3 archivos. |

No se ejecutaron MobSF, pruebas dinámicas móviles, una base de datos real, Docker ni un despliegue. MobSF está orientado a aplicaciones móviles; aquí se eligió CodeQL para el proyecto web. Tampoco se construyó la aplicación. Las bases y los informes SARIF sin publicar permanecen en una carpeta temporal local; pueden contener código o rutas y no deben subirse al repositorio. La limpieza recursiva previa fue rechazada por el entorno.

## Referencias

- [Documentación de CodeQL para crear bases de datos](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create).
- [Licencia y condiciones de CodeQL CLI](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md). Su uso está sujeto a sus condiciones; este reporte no determina la licencia del repositorio.
- [Documentación de MobSF](https://mobsf.github.io/docs/).
