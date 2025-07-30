# 🛡️ Hunting y Detección de NTLM Relay Attacks en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Autenticaciones NTLM sin NTLMv2 Session Security**
Busca autenticaciones NTLM que pueden ser susceptibles a relay attacks:
- **Log:** Security Event 4624 (Successful Logon)
- **Indicador clave:** LogonType=3 con AuthenticationPackageName=NTLM sin NTLMv2 Session Security

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search LogonType=3 AND AuthenticationPackageName=NTLM
| where isnull(LmPackageName) OR LmPackageName!="NTLM V2"
| table _time, TargetUserName, IpAddress, WorkstationName, LogonProcessName
| sort -_time
```
- **Revisa:** ¿Autenticaciones NTLM desde IPs no corporativas? ¿Workstation names sospechosos o inconsistentes?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Múltiples autenticaciones NTLM desde la misma IP a diferentes hosts**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search LogonType=3 AND AuthenticationPackageName=NTLM
| stats dc(ComputerName) as unique_targets count by IpAddress, TargetUserName
| where unique_targets > 3 AND count > 5
| sort -unique_targets
```
- Detecta patrón típico de NTLM relay: una IP atacando múltiples targets.

---

### **3. Autenticaciones NTLM con WorkstationName inconsistente**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search LogonType=3 AND AuthenticationPackageName=NTLM
| eval ip_vs_workstation=if(IpAddress!=WorkstationName AND WorkstationName!="", "MISMATCH", "OK")
| where ip_vs_workstation="MISMATCH"
| table _time, TargetUserName, IpAddress, WorkstationName, ComputerName
| sort -_time
```
- Identifica discrepancias entre IP origen y nombre de workstation reportado.

---

### **4. Correlación de fallos de autenticación seguidos de éxitos desde diferente IP**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4625
| search LogonType=3 AND AuthenticationPackageName=NTLM
| rename IpAddress as fail_ip, _time as fail_time, TargetUserName as username
| join username [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
    | rename IpAddress as success_ip, _time as success_time, TargetUserName as username
    | table username, success_ip, success_time, ComputerName
]
| where success_time > fail_time AND success_time < (fail_time + 300) AND fail_ip != success_ip
| table fail_time, username, fail_ip, success_time, success_ip, ComputerName
| sort -fail_time
```
- Detecta patrón de captura de hash seguido de relay exitoso.

---

### **5. Autenticaciones administrativas NTLM desde hosts no autorizados**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search LogonType=3 AND AuthenticationPackageName=NTLM
| search (TargetUserName="*admin*" OR TargetUserName="*svc*")
| lookup authorized_admin_hosts hostname as WorkstationName OUTPUT authorized
| where isnull(authorized) OR authorized="false"
| table _time, TargetUserName, IpAddress, WorkstationName, ComputerName
| sort -_time
```
- Identifica cuentas privilegiadas autenticando desde hosts no autorizados.

---

### **6. Detección de SMB relay mediante análisis de tráfico**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| search DestinationPort=445 AND NOT (DestinationIp="127.0.0.1" OR DestinationIp="::1")
| stats count dc(DestinationIp) as unique_destinations by SourceIp, Image
| where unique_destinations > 5 AND count > 10
| sort -unique_destinations
```
- Detecta conexiones SMB anómalas que pueden indicar relay attacks.

---

### **7. Uso de herramientas de NTLM relay**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (CommandLine="*ntlmrelayx*" OR CommandLine="*smbrelayx*" OR CommandLine="*MultiRelay*" OR Image="*responder*" OR CommandLine="*-smb2support*")
| table _time, Computer, Image, CommandLine, User, ParentImage
| sort -_time
```
- Identifica herramientas conocidas para NTLM relay attacks.

---

### **8. Autenticaciones NTLM durante horarios no laborales**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search LogonType=3 AND AuthenticationPackageName=NTLM
| eval hour=strftime(_time, "%H"), day_of_week=strftime(_time, "%w")
| where (hour < 6 OR hour > 22) OR day_of_week=0 OR day_of_week=6
| table _time, TargetUserName, IpAddress, WorkstationName, ComputerName
| sort -_time
```
- Detecta actividad NTLM fuera de horarios típicos de trabajo.

---

### **9. Detección de LLMNR/NBT-NS poisoning (precursor de relay)**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| search (QueryName="*wpad*" OR QueryName="*isatap*" OR QueryName="*teredo*")
| stats count by Computer, QueryName, QueryStatus
| where count > 10
| sort -count
```
- Identifica queries DNS que pueden ser targeted para poisoning attacks.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Más de 3 autenticaciones NTLM exitosas desde la misma IP a diferentes hosts en 10 minutos.
- **Alerta 2:**  
  Autenticación NTLM de cuenta administrativa desde IP no corporativa o host no autorizado.
- **Alerta 3:**  
  Discrepancia entre IpAddress y WorkstationName en autenticaciones NTLM.
- **Dashboard:**  
  - Panel de autenticaciones NTLM por IP origen y destinos únicos.
  - Panel de timeline de fallos seguidos de éxitos NTLM.
  - Panel geográfico de autenticaciones NTLM administrativas.
- **Integración con otros eventos:**  
  - Correlaciona con eventos de Sysmon (conexiones de red) para validation.
  - Integra con logs de DNS para detectar LLMNR/NBT-NS poisoning.
  - Cruza con eventos de file access para detectar lateral movement post-relay.

---

# NTLM Relay: Técnicas de ataque y su detección

1. **SMB Relay Attack (T1557.001)**
   - El atacante intercepta y relay autenticaciones NTLM via SMB.
   - **Detección:** Múltiples conexiones SMB desde una IP, autenticaciones NTLM sin NTLMv2.

2. **HTTP to SMB Relay**
   - Captura de credenciales via HTTP y relay a servicios SMB.
   - **Detección:** Autenticaciones NTLM cross-protocol, timing correlation.

3. **LDAP Relay for Privilege Escalation**
   - Relay de credenciales a LDAP para modificar permisos o crear cuentas.
   - **Detección:** Cambios en AD correlacionados con autenticaciones NTLM anómalas.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Implementa SMB signing obligatorio en todos los hosts del dominio.**
- Deshabilita LLMNR y NBT-NS donde no sean necesarios.
- Monitorea autenticaciones NTLM cross-subnet y cross-protocol.
- Considera migración a Kerberos donde sea posible.
- Implementa EPA (Extended Protection for Authentication) en servicios web.
- Despliega network segmentation para limitar scope de relay attacks.
- Usa canary hosts para detectar NTLM relay tempranamente.

---

## Tabla de Consultas SPL para Hunt for NTLM Relay Attacks

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM LmPackageName!="NTLM V2" \| table _time, TargetUserName, IpAddress, WorkstationName` | Detecta autenticaciones NTLM vulnerables a relay (sin NTLMv2 Session Security). |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM \| stats dc(ComputerName) as targets by IpAddress \| where targets > 3` | Identifica IPs atacando múltiples hosts (patrón de NTLM relay). |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM IpAddress!=WorkstationName \| table _time, TargetUserName, IpAddress, WorkstationName` | Detecta inconsistencias IP vs WorkstationName en autenticaciones NTLM. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*ntlmrelayx*" \| table _time, Computer, CommandLine, User` | Identifica uso de herramientas de NTLM relay como ntlmrelayx. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationPort=445 \| stats dc(DestinationIp) as targets by SourceIp \| where targets > 5` | Detecta conexiones SMB anómalas que pueden indicar relay. |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4625 LogonType=3 \| join TargetUserName [search EventCode=4624 LogonType=3] \| table _time, TargetUserName, IpAddress, ComputerName` | Correlaciona fallos y éxitos de autenticación para detectar relay patterns. |

---

## 🧠 Consejos finales de defensa y hunting

- **Habilita SMB signing y Channel Binding en todos los servicios críticos.**
- Implementa monitoring de cross-subnet NTLM authentication.
- Despliega honeypots con credenciales débiles para detectar relay attacks.
- Considera deshabilitar NTLM completamente en entornos donde sea posible.
- Automatiza detección de herramientas de NTLM relay en endpoints.
- Simula NTLM relay attacks en ejercicios red team para validar defensas.