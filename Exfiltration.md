## Tabla de Consultas SPL para Hunt for FTP Exfiltration
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=botsv2 ftp \| stats count by sourcetype \| sort - count" | Identifica sourcetypes disponibles con datos FTP para agosto de 2017. |
| "index=botsv2 ftp sourcetype=suricata \| stats count by src_ip dest_ip \| sort - count" | Busca indicadores de FTP en alertas de Suricata, identificando IPs involucradas. |
| "index=botsv2 ftp sourcetype=stream:ftp \| stats count by src_ip dest_ip \| sort - count" | Analiza flujos FTP para identificar sistemas internos comunicándose con 160.153.91.7. |
| "index=botsv2 ftp sourcetype=pan:traffic \| stats count by src_ip dest_ip \| sort - count" | Examina logs de Palo Alto para ver tráfico FTP hacia la interfaz externa del firewall. |
| "index=botsv2 ftp sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" \| stats count by host \| sort - count" | Identifica eventos Sysmon relacionados con FTP por host. |
| "index=botsv2 ftp sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" \| stats count by CommandLine" | Busca comandos FTP en eventos Sysmon para detectar actividad sospechosa. |
| "index=botsv2 ftp sourcetype=stream:ftp src_ip=* dest_ip=160.153.91.7" | Examina tráfico FTP hacia 160.153.91.7 para buscar exfiltración de datos. |
| "index=botsv2 sourcetype=stream:ftp src_ip=* dest_ip=160.153.91.7 method!=PORT method!=TYPE method!=NLST \| table _time src_ip filename method method_parameter reply_content \| sort + _time" | Refina la búsqueda de tráfico FTP para analizar archivos y respuestas específicas. |
| "index=botsv2 sourcetype=stream:ftp src_ip=* dest_ip=160.153.91.7 \| stats count by filename" | Identifica archivos específicos exfiltrados vía FTP hacia 160.153.91.7. |
| "index=botsv2 (singlefile.dll OR winsys32.dll) \| reverse" | Busca sourcetypes con información sobre las DLLs singlefile.dll y winsys32.dll. |
| "index=botsv2 sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" (singlefile.dll OR winsys32.dll) \| table _time host user CommandLine ParentCommandLine \| reverse" | Investiga eventos Sysmon relacionados con las DLLs sospechosas. |
| "index=botsv2 sourcetype=wineventlog (singlefile.dll OR winsys32.dll) \| stats count by host" | Analiza eventos de wineventlog para las DLLs sospechosas por host. |
| "index=botsv2 sourcetype!=stream:ftp (dns.py OR nc.exe OR psexec.exe OR python-2.7.6.amd64.msi OR wget64.exe OR winsys64.dll OR *.hwp) \| stats count by host" | Busca otros archivos descargados (dns.py, nc.exe, etc.) en hosts específicos. |
| "index=botsv2 sourcetype!=stream:ftp (dns.py OR nc.exe OR psexec.exe OR python-2.7.6.amd64.msi OR wget64.exe OR winsys64.dll OR *.hwp) \| reverse \| search host=\"venus\"" | Investiga eventos relacionados con archivos descargados en el host Venus. |
