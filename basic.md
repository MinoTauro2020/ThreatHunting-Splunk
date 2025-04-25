# Guía Completa de Comandos de Parseo y Análisis en Splunk (SPL)
Esta guía presenta los comandos de parseo y análisis más comunes del Search Processing Language (SPL) de Splunk, incluyendo los usados en los laboratorios "Effectively Using Splunk (Scenario 1 y 2)" y otros frecuentes en análisis de logs de seguridad. Cada comando se explica brevemente, con su propósito, uso típico, un ejemplo en un recuadro y una explicación, todo en una sola línea para facilitar la copia. La guía incluye consejos prácticos y una tabla de campos comunes.
## Comandos de Parseo y Análisis
### 1. metadata
- **Propósito**: Recupera metadatos (como tipos de fuentes, fuentes o hosts) de un índice sin analizar eventos completos, lo que lo hace rápido.
- **Uso típico**: Explorar `sourcetypes`, `sources` o `hosts` disponibles antes de una investigación.
- **Ejemplo**:

| metadata type=sourcetypes index="botsv1"

- **Explicación**: Lista todos los `sourcetypes` (e.g., `stream:dns`, `suricata`) en el índice `botsv1`.
### 2. fieldsummary
- **Propósito**: Genera un resumen de los campos presentes en los eventos, mostrando estadísticas como valores únicos y tipos de datos.
- **Uso típico**: Identificar campos relevantes en un conjunto de datos.
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns | fieldsummary | table field values

- **Explicación**: Resume los campos en eventos DNS, mostrando solo nombres de campos y sus valores.
### 3. timechart
- **Propósito**: Crea gráficos temporales de datos, agrupando eventos por tiempo y un campo específico.
- **Uso típico**: Visualizar tendencias o picos de actividad (e.g., accesos a URLs).
- **Ejemplo**:

index=botsv1 dest_ip=192.168.250.70 sourcetype=stream:http | timechart count by uri limit=10

- **Explicación**: Grafica el conteo de eventos por URL a lo largo del tiempo, limitando a las 10 URLs más frecuentes.
### 4. stats
- **Propósito**: Agrupa y calcula estadísticas (e.g., conteo, suma, valores únicos) sobre los datos.
- **Uso típico**: Contar eventos, listar valores únicos o agrupar por campos.
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns | stats count by query{}

- **Explicación**: Cuenta cuántas veces aparece cada dominio en consultas DNS.
### 5. table
- **Propósito**: Muestra resultados en una tabla con columnas específicas.
- **Uso típico**: Organizar datos para análisis o presentación.
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns query{}=cerberhhyed5frqa.xmfir0.win | table _time src_ip dest_ip query{}

- **Explicación**: Muestra tiempo, IPs de origen/destino y dominio en una tabla.
### 6. sort
- **Propósito**: Ordena resultados ascendente (`+`) o descendente (`-`) según un campo.
- **Uso típico**: Priorizar resultados (e.g., más frecuentes primero).
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns | stats count by query{} | sort - count

- **Explicación**: Ordena dominios DNS por conteo descendente.
### 7. rex
- **Propósito**: Extrae campos nuevos de un campo existente usando expresiones regulares (regex).
- **Uso típico**: Parsear datos estructurados (e.g., contraseñas en formularios).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http form_data=usernamepasswd* | rex field=form_data "passwd=(?<userpassword>\w+)"

- **Explicación**: Extrae la contraseña del campo `form_data` en un campo llamado `userpassword`.
### 8. dedup
- **Propósito**: Elimina eventos duplicados basados en un campo.
- **Uso típico**: Reducir ruido en resultados (e.g., consultas DNS repetidas).
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100 | table _time src_ip dest_ip query{} | dedup query{}

- **Explicación**: Elimina consultas DNS duplicadas, mostrando solo dominios únicos.
### 9. convert
- **Propósito**: Convierte valores de un campo a otro formato (e.g., epoch a tiempo humano).
- **Uso típico**: Hacer que los tiempos sean legibles.
- **Ejemplo**:

| metadata type=sources index="botsv1" | convert ctime(firstTime) as firstTime

- **Explicación**: Convierte el tiempo `firstTime` de epoch a formato legible (e.g., `MM/DD/YYYY HH:MM:SS`).
### 10. eval
- **Propósito**: Crea o modifica campos mediante cálculos o expresiones.
- **Uso típico**: Calcular valores (e.g., longitud de comandos).
- **Ejemplo**:

index="botsv1" source="wineventlog:microsoft-windows-sysmon/operational" | eval len=len(CommandLine)

- **Explicación**: Crea un campo `len` con la longitud del campo `CommandLine`.
### 11. search
- **Propósito**: Filtra resultados después de un comando, usando condiciones específicas.
- **Uso típico**: Refinar resultados (e.g., buscar un valor específico).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | rex field=form_data "passwd=(?<userpassword>\w+)" | search userpassword=batman

- **Explicación**: Filtra eventos donde la contraseña es `batman`.
### 12. lookup
- **Propósito**: Enriquce datos usando tablas de búsqueda externas para mapear valores.
- **Uso típico**: Analizar URLs o dominios (e.g., identificar subdominios).
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns | table query{} | lookup ut_parse_extended_lookup url as query{}

- **Explicación**: Usa una tabla de búsqueda para extraer subdominios, dominios y TLDs de consultas DNS.
### 13. ut_shannon (macro)
- **Propósito**: Calcula la entropía de un campo (e.g., subdominios) para detectar patrones generados algorítmicamente.
- **Uso típico**: Identificar dominios generados por malware (DGA).
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns | table query{} | lookup ut_parse_extended_lookup url as query{} | ut_shannon(ut_subdomain)

- **Explicación**: Calcula la entropía del subdominio para detectar dominios sospechosos.
### 14. rename
- **Propósito**: Cambia el nombre de un campo para hacerlo más legible o consistente.
- **Uso típico**: Renombrar campos extraídos o generados para claridad.
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | rex field=form_data "passwd=(?<pass>\w+)" | rename pass as Password

- **Explicación**: Renombra el campo `pass` a `Password` para mejor legibilidad.
### 15. top
- **Propósito**: Muestra los valores más frecuentes de un campo, con conteos y porcentajes.
- **Uso típico**: Identificar los elementos más comunes (e.g., IPs más activas).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | top limit=5 src_ip

- **Explicación**: Muestra las 5 IPs de origen más frecuentes en eventos HTTP, con su conteo y porcentaje.
### 16. rare
- **Propósito**: Muestra los valores menos frecuentes de un campo, con conteos y porcentajes.
- **Uso típico**: Detectar anomalías o eventos poco comunes.
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | rare limit=5 dest_port

- **Explicación**: Muestra los 5 puertos de destino menos frecuentes en eventos HTTP, con conteo y porcentaje.
### 17. join
- **Propósito**: Combina resultados de dos búsquedas basadas en un campo común, similar a un JOIN en SQL.
- **Uso típico**: Relacionar datos de diferentes `sourcetypes` (e.g., DNS y Sysmon).
- **Ejemplo**:

index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100 | table src_ip query{} | join src_ip [search index=botsv1 sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational SourceIp=192.168.250.100 | table SourceIp app]

- **Explicación**: Combina consultas DNS y Sysmon por `src_ip`, mostrando dominios y aplicaciones ejecutadas.
### 18. transaction
- **Propósito**: Agrupa eventos relacionados en una sola transacción basada en un campo común (e.g., sesión o usuario).
- **Uso típico**: Analizar secuencias de eventos (e.g., acciones de un atacante).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http src_ip=23.22.63.114 | transaction src_ip maxspan=1h

- **Explicación**: Agrupa eventos HTTP de la IP `23.22.63.114` en transacciones de máximo 1 hora.
### 19. eventstats
- **Propósito**: Calcula estadísticas (e.g., conteo, suma) y agrega los resultados como un campo a todos los eventos, sin agrupar.
- **Uso típico**: Añadir estadísticas globales a cada evento (e.g., total de eventos por IP).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | eventstats count by src_ip | table _time src_ip count

- **Explicación**: Añade un campo `count` con el total de eventos por `src_ip` a cada evento HTTP.
### 20. chart
- **Propósito**: Crea gráficos de datos agrupados por uno o más campos, similar a `stats` pero orientado a visualización.
- **Uso típico**: Generar gráficos personalizados (e.g., conteo por IP y método HTTP).
- **Ejemplo**:

index=botsv1 sourcetype=stream:http | chart count by src_ip http_method

- **Explicación**: Muestra un gráfico con el conteo de eventos por IP de origen y método HTTP (e.g., GET, POST).
### 21. append
- **Propósito**: Combina resultados de dos búsquedas diferentes, añadiendo los resultados de la segunda al final de la primera.
- **Uso típico**: Unir datos de diferentes `sourcetypes` sin relación directa.
- **Ejemplo**:

index=botsv1 sourcetype=stream:http src_ip=40.80.148.42 | table _time src_ip | append [search index=botsv1 sourcetype=suricata src_ip=40.80.148.42 | table _time src_ip]

- **Explicación**: Combina eventos HTTP y Suricata para la IP `40.80.148.42`, listándolos uno tras otro.
## Consejos para Usar Comandos
- **Filtra primero**: Usa `index`, `sourcetype` y campos como `src_ip` o `dest_ip` para reducir datos antes de aplicar `stats` o `timechart`.
- **Revisa campos**: Si un campo (e.g., `CommandLine`, `query{}`) no aparece, búscalo en "more fields" o usa `rex` para extraerlo.
- **Optimiza consultas**: Usa rangos de tiempo pequeños (e.g., `earliest=-24h`) y `Fast Mode` para consultas grandes.
- **Prueba paso a paso**: Ejecuta partes de la consulta (e.g., solo `index=botsv1 sourcetype=stream:dns`) para verificar datos antes de añadir comandos complejos.
- **Usa la interfaz**: Haz clic en campos en la columna izquierda de Splunk para explorar valores y detectar patrones.
## Campos Comunes en los Laboratorios
| **Campo**         | **Descripción**                                | **Sourcetype Ejemplo** |
|-------------------|------------------------------------------------|------------------------|
| src_ip            | IP de origen de la conexión                    | stream:http, stream:dns |
| dest_ip           | IP de destino de la conexión                   | stream:http, stream:dns |
| query{}           | Dominio consultado en DNS                      | stream:dns             |
| CommandLine       | Línea de comando ejecutada por un proceso      | WinEventLog:Microsoft-Windows-Sysmon/Operational |
| ParentCommandLine | Línea de comando del proceso padre             | WinEventLog:Microsoft-Windows-Sysmon/Operational |
| app               | Aplicación o ejecutable                        | WinEventLog:Microsoft-Windows-Sysmon/Operational |
| dest_port         | Puerto de destino de la conexión               | WinEventLog:Microsoft-Windows-Sysmon/Operational |
| form_data         | Datos de formularios HTTP (e.g., credenciales) | stream:http            |
| md5               | Hash MD5 de un archivo                         | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |
| http_method       | Método HTTP (e.g., GET, POST)                  | stream:http            |
| sc_status         | Código de estado HTTP (e.g., 200)              | iis                    |

