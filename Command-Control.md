## Tabla de Consultas SPL para Hunt for PowerShell Empire
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=botsv2 sourcetype=stream:tcp ssl_issuer=\"C = US\"" | Identifica sistemas internos usando certificados SSL con issuer "C = US", común en PowerShell Empire. |
| "index=botsv2 sourcetype=stream:tcp ssl_issuer=\"C = US\" \| top src_ip dest_ip \| sort - count" | Acelera la búsqueda anterior usando tstats para identificar IPs origen y destino con el issuer "C = US". |
| "| datamodel \| spath displayName \| stats values(displayName)" | Lista todos los datamodels disponibles en el entorno para explorar datos estructurados. |
| "index=botsv2 45.77.65.211 \| stats count by sourcetype \| sort - count" | Identifica sourcetypes con eventos relacionados con el IP indicador 45.77.65.211 (web y Sysmon). |
| "index=botsv2 45.77.65.211 sourcetype=pan:traffic \| stats count by src_ip dest_ip \| sort - count" | Analiza logs de firewall Palo Alto para ver qué sistemas se comunicaron más con 45.77.65.211. |
| "index=botsv2 45.77.65.211 sourcetype=suricata \| stats count by src_ip dest_ip \| sort - count" | Examina alertas de Suricata para identificar comunicaciones con 45.77.65.211. |
| "index=botsv2 src=45.77.65.211 sourcetype=suricata" | Busca alertas inbound de Suricata desde 45.77.65.211 para analizar firmas de ataque. |
| "index=botsv2 45.77.65.211 sourcetype=stream:http \| stats count by src_ip dest_ip \| sort - count" | Identifica flujos de comunicación HTTP con 45.77.65.211 para investigar IPs específicas. |
| "index=botsv2 sourcetype=stream:http src_ip=45.77.65.211 dest_ip=172.31.4.249" | Analiza eventos HTTP entre 45.77.65.211 y el servidor Linux 172.31.4.249 para buscar actividad maliciosa. |
| "index=botsv2 45.77.65.211 sourcetype=stream:http 71.39.18.125" | Investiga comunicaciones HTTP entre 45.77.65.211 y la interfaz externa del firewall 71.39.18.125. |
| "index=botsv2 45.77.65.211 sourcetype=stream:http src_ip=10.0.2.109" | Examina comunicaciones HTTP desde 10.0.2.109 hacia 45.77.65.211 para buscar indicios de PowerShell Empire. |
| "index=botsv2 45.77.65.211 sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" \| stats count by src_ip dest_ip \| sort - count" | Busca eventos Sysmon relacionados con 45.77.65.211 para identificar sistemas comprometidos. |
| "index=botsv2 sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" dest=45.77.65.211*" | Identifica eventos Sysmon con destino 45.77.65.211, enfocándose en procesos como PowerShell. |
| "index=botsv2 sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" dest=45.77.65.211* \| stats values(dest_port) as dest_port values(host) as host values(src_ip) as src_ip values(src_port) as src_port by process,dest,user" | Analiza eventos de conexión de red de PowerShell hacia 45.77.65.211, incluyendo puertos y usuarios. |
| "index=botsv2 sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" dest_ip=45.77.65.211* user=FROTHLY\\service3 \| timechart count by src_ip" | Visualiza la actividad de red del usuario service3 hacia 45.77.65.211 entre 8/23 y 8/26. |
| "index=\"botsv2\" sourcetype=\"xmlwineventlog:microsoft-windows-sysmon/operational\" user=FROTHLY\\service3 \| stats values(CommandLine) by Computer,process,ParentImage" | Investiga comandos ejecutados por el usuario service3, buscando actividad maliciosa de PowerShell. |
