## Tabla de Consultas SPL para Hunt for Renamed PowerShell
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=winsysmon EventCode=1 AND Description=\"Windows PowerShell\" AND (Image!=\"*\\powershell.exe\" AND Image!=\"*\\powershell_ise.exe\") \| rex field=Hashes \".*MD5=(?<MD5>[A-F0-9]*),\" \| table _time, Computer, User, Image, cmdline, ParentImage, MD5" | Detecta procesos con descripción "Windows PowerShell" que no sean powershell.exe ni powershell_ise.exe. |
| "index=winsysmon EventCode=1 AND Description=\"Windows PowerShell\" \| rex field=Hashes \".*MD5=(?<MD5>[A-F0-9]*),\" \| stats dc(Computer) AS Hostname count by Image MD5 Description \| sort -count" | Proporciona una visión general de las versiones de PowerShell ejecutadas en el entorno. |

## Tabla de Consultas SPL para Hunt for PowerShell Empire
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=* EventCode=4104 AND ($psversiontable.psversion.major OR system.management.automation.utils OR system.management.automation.amsiutils) \| eval MessageDeobfuscated = replace(Message, \"[ `'+\\\"\\^]\",\"\") \| search EnableScriptBlockLogging OR enablescriptblockinvocationlogging OR cachedgrouppolicysettings OR ServerCertificateValidationCallback OR expect100continue \| table _time ComputerName Sid MessageDeobfuscated" | Detecta actividad maliciosa de PowerShell Empire buscando cadenas específicas y desofuscando comandos. |

## Tabla de Consultas SPL para Hunt for Unmanaged PowerShell
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=* hostapplication \| rex field=Message \".*HostApplication=(?<HostApplication>.*)\" \| search HostApplication!=\"*powershell*\" HostApplication!=\"*\\sdiagnhost.exe*\" \| stats count by host HostApplication" | Detecta instancias de PowerShell no gestionadas filtrando aplicaciones host conocidas. |

## Tabla de Consultas SPL para Hunt for PowerShell Base64 Encoded Commands
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=* EventCode=1 \| eval cmdline =replace(cmdline, \"-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]\", \"__encoding\") \| search Image=\"*\\powershell.exe\" (cmdline=\"* -enc*\" OR cmdline=\"* -en *\" OR cmdline=\"* -e *\" OR cmdline=\"* -ec *\") \| table _time Computer User ParentImage ParentCommandLine" | Detecta comandos codificados en Base64 ejecutados por PowerShell, mostrando procesos padre. |
| "index=* EventCode=1 \| eval cmdline =replace(cmdline, \"-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]\", \"__encoding\") \| search Image=\"*\\powershell.exe\" (cmdline=\"* -enc*\" OR cmdline=\"* -en *\" OR cmdline=\"* -e *\" OR cmdline=\"* -ec *\") \| table _time Computer User cmdline" | Muestra los comandos codificados en Base64 ejecutados por PowerShell para análisis detallado. |

