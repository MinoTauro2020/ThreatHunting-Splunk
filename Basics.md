## Tabla de Comandos de Parseo y Análisis en Splunk (SPL)
| **Comando**       | **Descripción**                                              | **Ejemplo**                                       |
|-------------------|--------------------------------------------------------------|---------------------------------------------------|
| search            | Busca eventos en los índices de Splunk basados en criterios específicos. | "\| search index=main sourcetype=access_combined status=404" |
| stats             | Calcula estadísticas sobre los eventos, como conteos, sumas, promedios, etc. | "\| stats count by host"                         |
| table             | Muestra los resultados en una tabla con columnas específicas. | "\| table _time host source"                      |
| sort              | Ordena los resultados ascendente o descendente basado en un campo. | "\| stats count by host \| sort - count"          |
| rex               | Extrae campos nuevos de los eventos usando expresiones regulares. | "\| rex field=_raw \"user=(?<user>\w+)\""         |
| dedup             | Elimina eventos duplicados basados en uno o más campos.     | "\| dedup host source"                            |
| eval              | Crea o modifica campos mediante cálculos o expresiones.     | "\| eval duration=end_time - start_time"          |
| lookup            | Enriquecer los eventos con datos de una tabla de búsqueda externa. | "\| lookup my_lookup_table field1 OUTPUT field2"  |
| where             | Filtra los resultados basados en condiciones después de otros comandos. | "\| stats count by host \| where count > 1000"    |
| join              | Combina resultados de dos búsquedas basados en un campo común. | "\| table host, action \| join host [search index=main \| table host, status]" |
| transaction       | Agrupa eventos relacionados en una transacción basada en un campo. | "\| transaction session_id"                       |
| chart             | Crea gráficos agrupados por uno o más campos.               | "\| chart count by host status"                   |
| append            | Combina resultados de dos búsquedas añadiendo una tras otra. | "\| append [search index=main \| stats count by host]" |
| top               | Muestra los valores más frecuentes de un campo.              | "\| top limit=5 host"                             |
| rare              | Muestra los valores menos frecuentes de un campo.            | "\| rare limit=5 status"                          |
| fieldsummary      | Resume los campos presentes en los eventos con estadísticas. | "\| fieldsummary"                                 |
| timechart         | Crea gráficos temporales agrupando eventos por tiempo.       | "\| timechart count by host"                      |
| metadata          | Recupera metadatos de un índice, como sourcetypes, hosts, etc. | "\| metadata type=sourcetypes index=main"         |
| rename            | Cambia el nombre de un campo para mayor legibilidad.         | "\| rename host as HostName"                      |
| convert           | Convierte valores de un campo a otro formato, como epoch a tiempo legible. | "\| convert ctime(_time) as human_time"           |
| eventstats        | Calcula estadísticas y las agrega como campos a todos los eventos. | "\| eventstats count by host"                     |
| fields            | Selecciona o elimina campos específicos para mostrar.        | "\| fields host, source, _time"                   |
| fillnull          | Rellena valores nulos en campos con un valor especificado.   | "\| fillnull value=0 field=duration"              |
| streamstats       | Calcula estadísticas acumulativas sobre eventos en orden.    | "\| streamstats count by host"                    |
| head              | Muestra los primeros N eventos de los resultados.            | "\| head 10"                                      |
| tail              | Muestra los últimos N eventos de los resultados.             | "\| tail 10"                                      |
| uniq              | Muestra valores únicos de un campo, similar a dedup.         | "\| uniq host"                                    |
