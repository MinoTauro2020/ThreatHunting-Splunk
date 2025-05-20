## Tabla de Consultas SPL para Hunt for WMI Persistence
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=winsysmon EventCode=19 OR EventCode=20 OR EventCode=21 \| table _time, EventCode, EventDescription, Operation, Computer, Consumer, Query, Destination" | Busca eventos WMI de Sysmon (IDs 19, 20, 21) para detectar persistencia WMI, mostrando detalles del archivo ejecutado. |

## Tabla de Consultas SPL para Hunt for Filesystem Persistence
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=\"winsysmon\" EventCode=1 Image=\"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*\" OR CommandLine=\"*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*\" \| table _time Computer User Image CommandLine MD5" | Detecta procesos iniciados desde la carpeta Startup para persistencia en el sistema de archivos. |
