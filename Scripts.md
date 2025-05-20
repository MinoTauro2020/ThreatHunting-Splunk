## Tabla de Consultas SPL para Hunt for Logon Scripts
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=winsysmon ((ParentImage=\"*\\userinit.exe\" NOT (Image=\"*\\explorer.exe\")) NOT ((CommandLine=\"*\\netlogon.bat\" OR CommandLine=\"*\\UsrLogon.cmd\"))) \| stats values(cmdline) dc(Computer) AS hosts count by ParentImage Image" | Detecta scripts de inicio de sesión ejecutados por userinit.exe, excluyendo procesos legítimos como explorer.exe. |
| "index=winsysmon ((EventCode=\"11\" OR EventCode=\"12\" OR EventCode=\"13\" OR EventCode=\"14\") AND TargetObject=\"*UserInitMprLogonScript*\") \| table Computer, EventCode, signature, TargetObject, Details" | Busca actividad en el registro (Sysmon IDs 11, 12, 13, 14) relacionada con la clave UserInitMprLogonScript. |

## Tabla de Consultas SPL para Hunt for Suspicious VBS Scripts
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=\"winsysmon\" EventCode=1 Image=\"*\\cscript.exe\" OR Image=\"*\\wscript.exe\" \| rex field=Image \".*\\\\(?<Image_fn>[^\\\\]*)\" \| rex field=ParentImage \".*\\\\(?<ParentImage_fn>[^\\\\]*)\" \| stats count by Computer User ProcessId Image CommandLine ParentImage ParentCommandLine" | Detecta scripts VBS ejecutados por cscript.exe o wscript.exe, mostrando detalles para análisis. |
