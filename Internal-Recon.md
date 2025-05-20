## Tabla de Consultas SPL para Hunt for Internal Recon
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=\"winsysmon\" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe \| bin _time span=15m \| stats dc(Image) AS CNT_CMDS values(CommandLine) values(ParentCommandLine) count by _time Computer User \| where CNT_CMDS > 2" | Detecta actividad de reconocimiento interno ejecutando múltiples comandos en 15 minutos. |

