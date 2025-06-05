# 🛡️ Hunting y Detección de Kerberoasting en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Solicitudes TGS sospechosas (evento 4769, Ticket_Encryption_Type=0x17/23)**
Busca todas las solicitudes de tickets de servicio Kerberos (TGS) donde el cifrado utilizado es RC4-HMAC (0x17 o 23), ya que son vulnerables a Kerberoasting.  
**Esta es la señal principal de Kerberoasting.**

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| table _time, Account_Name, Service_Name, Client_Address, ComputerName
```
- **Revisa:** ¿Qué cuentas (Service_Name) están siendo objetivo? ¿Quién pide los tickets (Account_Name)? ¿Desde qué IP? ¿Hay patrones de repetición anómalos?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Solicitudes masivas de TGS desde una misma IP**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| stats count by Client_Address, Account_Name
| where count > 5
```
- IPs que solicitan hashes de múltiples cuentas (patrón típico de ataque automático).

---

### **3. Solicitudes a cuentas privilegiadas o críticas**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*" OR Service_Name="*sql*" OR Service_Name="*backup*"
| table _time, Service_Name, Account_Name, Client_Address
```
- Si el ataque va dirigido a cuentas sensibles: alerta máxima.

---

### **4. Solicitudes repetidas de TGS para la misma cuenta de servicio**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| stats count by Service_Name, Account_Name, Client_Address
| where count > 3
| sort -count
```
- Detecta intentos de Kerberoasting automáticos o repetidos contra una misma cuenta crítica.

---

### **5. Solicitudes desde redes externas o no confiables**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Service_Name, Account_Name, Client_Address
```
- Altamente sospechoso: Kerberoasting lanzado desde fuera de la red corporativa.

---

### **6. Correlación con logons previos de la misma IP**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| rename Account_Name as kerb_user, Client_Address as kerb_ip, _time as kerb_time
| join kerb_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=kerb_ip AND logon_time < kerb_time
| table kerb_time, kerb_user, kerb_ip, logon_user, logon_time
| sort kerb_time, kerb_ip, logon_time
```
- ¿La IP ya tenía actividad legítima previa o es un origen nuevo en la red?

---

### **7. Solicitudes sin actividad legítima previa por esa IP**
```splunk
... | stats count by kerb_time, kerb_ip | where count=0
```
- Encuentra IPs que solo aparecen en eventos de Kerberoasting.

---

### **8. Solicitudes a cuentas con SPN y privilegios elevados**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*" OR Service_Name="*sql*" OR Service_Name="*backup*"
| stats count by Account_Name, Service_Name, Client_Address
| where count > 3
| sort -count
```
- Priorización de hallazgos en cuentas más críticas y de alto impacto.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Más de 3 eventos 4769 con Ticket_Encryption_Type=0x17/23 desde la misma IP en menos de 1 minuto.
- **Alerta 2:**  
  Solicitud de TGS a cuentas privilegiadas (`Service_Name` coincidente con patrones críticos).
- **Dashboard:**  
  - Panel por volumen de 4769 RC4-HMAC por IP.
  - Panel de cuentas objetivo más atacadas.
  - Panel de origen de las solicitudes sospechosas.
- **Integración con otros eventos:**  
  - Correlaciona con eventos 4625/4740 para ver intentos de acceso fallidos o bloqueos desde la misma IP.
  - Añade panel de cambios en cuentas de servicio y rotación de contraseñas.
  - Cruza con logs de firewall para detectar accesos desde ubicaciones externas.

---

# Kerberoasting: Formas de ataque y su detección

1. **Ataque interno desde cuenta autenticada**
   - El atacante usa una cuenta legítima para solicitar TGS de múltiples cuentas de servicio.
   - **Detección:** Solicitudes anómalas de TGS desde un usuario común, con patrones de repetición o volumen inusual.

2. **Enumeración automatizada de cuentas de servicio**
   - El atacante enumera todos los SPN y solicita tickets en masa.
   - **Detección:** Una sola IP solicitando muchos TGS para diferentes servicios, especialmente bajo RC4.

3. **Ataque dirigido a cuentas privilegiadas**
   - El atacante conoce y ataca cuentas críticas de manera puntual pero repetida.
   - **Detección:** Solicitudes de TGS a cuentas con nombres o patrones de alto valor.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Empieza siempre por el evento 4769 con Ticket_Encryption_Type=0x17/23.**
- Afina por volumen, origen, cuentas críticas, repetición y actividad previa de la IP.
- Documenta hallazgos y automatiza alertas sobre los patrones anteriores.
- Integra con fuentes externas (AD, firewall, EDR) para enriquecer la investigación.
- Considera rotar credenciales y forzar cifrado AES en cuentas encontradas vulnerables.
- Despliega campañas de concienciación y simula Kerberoasting en ejercicios purple/red para validar defensas.

---

## Tabla de Consultas SPL para Hunt for Kerberoasting
| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| "index=\"ad_hunting\" source=XmlWinEventLog:Security EventCode=4769 (TicketEncryptionType=0x1 OR TicketEncryptionType=0x3 OR TicketEncryptionType=0x17 OR TicketEncryptionType=0x18) \| eval Source=if(IpAddress=\"::1\", Computer, IpAddress) \| table _time, host, Source, TargetUserName, ServiceName, TicketEncryptionType \| sort - _time \| rename _time AS \"Time\", host AS \"Host\", TargetUserName AS \"Target Username\", ServiceName AS \"Service Name\", TicketEncryptionType AS \"Ticket Encryption\" \| convert ctime(Time)" | Detecta solicitudes de tickets de servicio con cifrado débil, indicativo de Kerberoasting. |
| "index=\"ad_hunting\" source=XmlWinEventLog:Security EventCode=4769 ServiceName != krbtgt \| regex ServiceName != \"\\$$\" \| transaction IpAddress maxpause=5m maxevents=-1 \| eval services=mvcount(ServiceName) \| where services > 1 \| eval Source=if(IpAddress=\"::1\", Computer, IpAddress) \| table _time, host, Source, TargetUserName, services, ServiceName, TicketEncryptionType \| sort - _time \| rename _time AS \"Time\", host AS \"Host\", TargetUserName AS \"Target Username\", services AS \"Number of Services\", ServiceName AS \"Service Name\", TicketEncryptionType AS \"Ticket Encryption\" \| convert ctime(Time)" | Detecta solicitudes excesivas de tickets de servicio desde una fuente. |
| "index=\"ad_hunting\" source=XmlWinEventLog:Security EventCode=4769 IpPort > 0 (IpPort < 1024 OR (NOT (IpAddress=10.0.0.0/8 OR IpAddress=172.16.0.0/12 OR IpAddress=192.168.0.0/16 OR IpAddress=127.0.0.1 OR IpAddress=::1))) \| table _time, host, IpAddress, IpPort, TargetUserName, ServiceName, TicketEncryptionType \| sort - _time \| rename _time AS \"Time\", host AS \"Host\", IpAddress AS Source, IpPort AS \"Source Port\", TargetUserName AS \"Target Username\", ServiceName AS \"Service Name\", TicketEncryptionType AS \"Ticket Encryption\" \| convert ctime(Time)" | Detecta solicitudes de tickets de servicio desde direcciones externas o puertos inusuales. |
| "index=\"ad_hunting\" source=XmlWinEventLog:Security EventCode=4769 ServiceName=Honeypot01 \| eval Source=if(IpAddress=\"::1\", Computer, IpAddress) \| table _time, host, Source, TargetUserName, ServiceName, TicketEncryptionType \| sort - _time \| rename _time AS \"Time\", host AS \"Host\", TargetUserName AS \"Target Username\", ServiceName AS \"Service Name\", TicketEncryptionType AS \"Ticket Encryption\" \| convert ctime(Time)" | Detecta solicitudes de tickets hacia una cuenta honeypot, indicativo de Kerberoasting. |
| "index=\"ad_hunting\" source=\"WinEventLog:Microsoft-Windows-PowerShell/Operational\" (EventCode=4103 OR EventCode=4104) \| transaction Computer maxpause=15m maxevents=-1 \| eval raw=_raw \| search [\| inputlookup service_accounts.csv \| eval raw=\"*\" . account . \"*\" \| fields raw] \| where eventcount > 2 \| table _time, Computer, eventcount \| sort - _time \| rename _time AS \"Time\", Computer AS \"Host\", eventcount AS \"Number of Events\" \| convert ctime(Time)" | Detecta manipulación de cuentas de servicio vía PowerShell (sin resultados en este lab). |

