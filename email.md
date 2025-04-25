## Tabla de Consultas SPL para Investigar Intrusión Inicial por Correo Electrónico
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=o365 sourcetype=o365_management_activity Operation=UserLoggedIn \| stats count by user_id src_ip" | Identifica accesos sospechosos a cuentas O365, agrupando por usuario e IP de origen. |
| "index=o365 sourcetype=o365_management_activity Workload=Exchange Operation=MailItemsAccessed \| table _time user_id MailboxOwnerUPN Operation" | Detecta accesos a elementos de correo (e.g., lectura de emails) por usuarios o atacantes. |
| "index=o365 sourcetype=o365_management_activity Operation=SearchCreated \| table _time user_id Query ExchangeLocations" | Busca búsquedas de contenido en Purview Compliance que podrían indicar recolección de datos. |[](https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-dissecting-email-collection-techniques.html)
| "index=o365 sourcetype=o365_management_activity Operation=Set-Mailbox Forwarding* \| table _time user_id ForwardingSmtpAddress" | Identifica reglas de reenvío de correo creadas para exfiltrar emails. |[](https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-dissecting-email-collection-techniques.html)
| "index=main sourcetype=stream:smtp *.eml \| rex field=body \"From: <(?<sender>[^>]+)>\" \| table _time sender" | Extrae direcciones de remitentes de correos electrónicos para detectar phishing. |
| "index=main sourcetype=sysmon EventCode=11 *.zip *.exe \| table _time FileName ProcessName" | Detecta archivos sospechosos (e.g., adjuntos maliciosos) creados en el sistema. |[](https://www.splunk.com/en_us/blog/security/monitor-for-investigate-and-respond-to-phishing-payloads-with-splunk-enterprise-security-content-update.html)
| "index=main sourcetype=suricata email attachment *.exe \| table _time src_ip dest_ip fileinfo.filename" | Identifica adjuntos ejecutables enviados o recibidos a través de correo. |
| "index=o365 sourcetype=o365_management_activity Operation=AdminMailAccess \| stats count by UserId MailboxId" | Detecta accesos administrativos a buzones que podrían indicar abuso de privilegios. |[](https://research.splunk.com/cloud/c6998a30-fef4-4e89-97ac-3bb0123719b4/)
| "index=main sourcetype=stream:dns query{}=\"*.win\" \| stats count by query{} src_ip" | Busca dominios sospechosos (e.g., DGA) en consultas DNS relacionadas con phishing. |
| "index=main sourcetype=azure:ad:signinlogs ResultType!=0 \| table _time UserPrincipalName SrcIpAddress ResultDescription" | Identifica intentos de inicio de sesión fallidos en Azure AD que podrían indicar password spraying. |[](https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-blue-team-s-guide-to-initial-access-vectors.html)

## Tabla de Consultas SPL para Detectar Archivos .exe o .zip en Correos Electrónicos
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=main sourcetype=stream:smtp *.exe *.zip \| table _time src_ip dest_ip body" | Busca correos electrónicos con adjuntos .exe o .zip en tráfico SMTP. |
| "index=main sourcetype=suricata email attachment *.exe *.zip \| table _time src_ip dest_ip fileinfo.filename" | Detecta adjuntos .exe o .zip en correos electrónicos a través de alertas Suricata. |
| "index=main sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11 *.exe *.zip \| table _time FileName ProcessName" | Identifica archivos .exe o .zip creados en el sistema, posiblemente desde un correo. |
| "index=o365 sourcetype=o365_management_activity Workload=Exchange Operation=MailItemsAccessed *.exe *.zip \| table _time user_id MailboxOwnerUPN" | Busca accesos a correos con adjuntos .exe o .zip en Exchange (O365). |
| "index=main sourcetype=stream:smtp *.eml *.exe *.zip \| rex field=body \"Content-Disposition: attachment; filename=\\\"(?<filename>[^\\\"]+)\\\"\\s*Content-Type:.*(zip|exe)\" \| table _time filename" | Extrae nombres de adjuntos .exe o .zip de correos electrónicos. |
| "index=main sourcetype=suricata email *.exe *.zip \| stats count by src_ip fileinfo.filename" | Cuenta correos con adjuntos .exe o .zip por IP de origen según Suricata. |
| "index=main sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational EventCode=1 CommandLine=*.exe CommandLine=*.zip \| table _time CommandLine ProcessName" | Detecta procesos iniciados desde .exe o .zip, posiblemente de un correo. |
| "index=o365 sourcetype=o365_management_activity Operation=AttachmentDownloaded *.exe *.zip \| table _time user_id AttachmentName" | Identifica descargas de adjuntos .exe o .zip desde O365 Exchange. |
| "index=main sourcetype=stream:smtp *.exe *.zip \| rex field=body \"From: <(?<sender>[^>]+)>\" \| table _time sender filename" | Asocia adjuntos .exe o .zip con el remitente del correo electrónico. |
| "index=main sourcetype=suricata email attachment *.exe *.zip dest_ip=192.168.250.* \| table _time src_ip dest_ip fileinfo.filename" | Busca adjuntos .exe o .zip enviados a IPs locales (e.g., red interna). |

