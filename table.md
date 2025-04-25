## Tabla de Comandos de Parseo y Análisis en Splunk (SPL)
| **Comando**       | **Descripción**                                              | **Ejemplo**                                       |
|-------------------|--------------------------------------------------------------|---------------------------------------------------|
| metadata          | Recupera metadatos (e.g., sourcetypes, hosts) de un índice   | "\| metadata type=sourcetypes index=main"         |
| fieldsummary      | Resume campos presentes en eventos con estadísticas          | "index=main \| fieldsummary"                      |
| timechart         | Crea gráficos temporales agrupando eventos por tiempo        | "index=main \| timechart count by uri"            |
| stats             | Agrupa y calcula estadísticas (e.g., conteo, valores únicos) | "index=main \| stats count by host"               |
| table             | Muestra resultados en una tabla con columnas específicas     | "index=main \| table _time host"                  |
| sort              | Ordena resultados ascendente o descendente por un campo      | "index=main \| stats count by host \| sort - count" |
| rex               | Extrae campos nuevos usando expresiones regulares (regex)    | "index=main \| rex \"user=(?<user>\w+)\""         |
| dedup             | Elimina eventos duplicados basados en un campo               | "index=main \| dedup host"                        |
| convert           | Convierte valores de un campo a otro formato (e.g., epoch)   | "\| metadata index=main \| convert ctime(_time)"  |
| eval              | Crea o modifica campos mediante cálculos o expresiones       | "index=main \| eval len=len(message)"             |
| search            | Filtra resultados después de un comando con condiciones      | "index=main \| search status=200"                 |
| lookup            | Enriquce datos usando tablas de búsqueda externas            | "index=main \| lookup users user as user"         |
| ut_shannon        | Calcula la entropía de un campo para detectar patrones DGA   | "index=main \| `ut_shannon(host)`"                |
| rename            | Cambia el nombre de un campo para mayor legibilidad          | "index=main \| rename host as HostName"           |
| top               | Muestra los valores más frecuentes de un campo               | "index=main \| top limit=5 host"                  |
| rare              | Muestra los valores menos frecuentes de un campo             | "index=main \| rare limit=5 status"               |
| join              | Combina resultados de dos búsquedas por un campo común       | "index=main \| join host [search index=sec]"      |
| transaction       | Agrupa eventos relacionados en una transacción por un campo  | "index=main \| transaction host"                  |
| eventstats        | Calcula estadísticas y las agrega como campos a todos los eventos | "index=main \| eventstats count by host"         |
| chart             | Crea gráficos agrupados por uno o más campos, no temporales  | "index=main \| chart count by host status"        |
| append            | Combina resultados de dos búsquedas añadiendo una tras otra  | "index=main \| append [search index=sec]"         |
