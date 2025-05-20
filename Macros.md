## Tabla de Consultas SPL para Hunt for Malicious Word Document
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=\"winsysmon\" EventCode=1 ParentImage=*\\winword.exe \| table _time Computer User Image ParentImage ParentCommandLine" | Busca procesos iniciados por winword.exe, indicando posible ejecución de macros maliciosas. |
