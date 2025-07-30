# 🛡️ Hunting y Detección de Golden Ticket (Forged Kerberos TGT) en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. TGTs con lifetime anómalos (evento 4769 con valores fuera de política)**
Busca tickets TGS generados desde TGTs forjados que no respetan las políticas de tiempo del dominio:
- **Log:** Security Event 4769 (Ticket Solicitado de Servicio Kerberos)
- **Indicador clave:** Tickets con lifetime excesivos o inconsistentes con políticas de dominio

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| eval ticket_lifetime=case(
    Ticket_Options LIKE "*0x50810000*", "Lifetime_Suspicious_Forged",
    Ticket_Options LIKE "*0x50800000*", "Lifetime_Suspicious_Extended", 
    1=1, "Normal"
)
| where ticket_lifetime!="Normal"
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Options, ticket_lifetime
| sort -_time
```
- **Revisa:** ¿Hay TGTs con lifetime de 10 años (indicador clásico de Golden Ticket)? ¿Tickets que no expiran según política del dominio?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. TGTs autenticados fuera de DCs conocidos**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| search NOT (ComputerName="DC01" OR ComputerName="DC02" OR ComputerName="DC-PROD*")
| where TicketEncryptionType="0x12" OR TicketEncryptionType="0x17"
| table _time, Account_Name, Client_Address, ComputerName, TicketEncryptionType
| sort -_time
```
- TGTs generados desde hosts que no son controladores de dominio = probable Golden Ticket.

---

### **3. Solicitudes TGS con TGTs forjados (PAC validation bypass)**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| join type=left Account_Name [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
    | rename Account_Name as tgt_account, _time as tgt_time
    | table tgt_account, tgt_time, TicketEncryptionType
]
| where isnull(tgt_time) OR (tgt_time > _time)
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
| sort -_time
```
- Detecta solicitudes TGS sin TGT previo válido = uso de Golden Ticket.

---

### **4. Autenticación con cuentas privilegiadas desde IPs inusuales**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| search (Account_Name="*admin*" OR Account_Name="krbtgt" OR Account_Name="*svc*")
| lookup geoip clientip as Client_Address
| stats count by Account_Name, Client_Address, Country, City
| where count < 3 AND Country!="Local_Network"
| sort -count
```
- Cuentas críticas autenticando desde ubicaciones geográficas inusuales.

---

### **5. Detección de TGT con encriptación RC4 para cuentas que soportan AES**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| where TicketEncryptionType="0x17" OR TicketEncryptionType="23"
| join Account_Name [
    | ldapsearch domain=dc=domain,dc=com search="(&(objectCategory=person)(msDS-SupportedEncryptionTypes=*))"
    | where match(msDS-SupportedEncryptionTypes, ".*AES.*")
    | table sAMAccountName
    | rename sAMAccountName as Account_Name
]
| table _time, Account_Name, Client_Address, TicketEncryptionType
| sort -_time
```
- Cuentas configuradas para AES pero generando tickets RC4 = posible Golden Ticket con hash NT.

---

### **6. Correlación de autenticación con eventos de logon anómalos**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| rename Account_Name as kerb_user, Client_Address as kerb_ip, _time as kerb_time
| join kerb_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 LogonType=3
    | rename TargetUserName as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time, LogonType, WorkstationName
]
| where kerb_user!=logon_user OR abs(kerb_time-logon_time) > 300
| table kerb_time, kerb_user, kerb_ip, logon_user, logon_time, WorkstationName
| sort -kerb_time
```
- Detecta inconsistencias entre autenticación Kerberos y logon events.

---

### **7. Análisis de TGT con SID History anómalo**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| regex PreAuthType=".*"
| where PreAuthType!="15" AND PreAuthType!="2"
| table _time, Account_Name, Client_Address, PreAuthType, Status
| sort -_time
```
- PreAuth types inusuales pueden indicar Golden Tickets con SID History manipulado.

---

### **8. Detección de uso de Golden Ticket para DCSync**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4662
| where (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| join SubjectLogonId [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
    | rename TargetLogonId as SubjectLogonId, Account_Name as tgt_account
    | table SubjectLogonId, tgt_account, Client_Address, TicketEncryptionType
]
| where TicketEncryptionType="0x17"
| table _time, SubjectUserName, tgt_account, Client_Address, ObjectName
| sort -_time
```
- Golden Tickets utilizados para realizar DCSync attacks.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  TGT generado fuera de controladores de dominio conocidos (EventCode 4768 desde hosts no-DC).
- **Alerta 2:**  
  Solicitudes TGS sin TGT previo válido en ventana de tiempo de 5 minutos.
- **Alerta 3:**  
  Cuentas privilegiadas autenticando con RC4 cuando están configuradas para AES.
- **Dashboard:**  
  - Panel de TGTs por encryption type y origen geográfico.
  - Panel de timeline de autenticación para cuentas críticas.
  - Panel de correlación TGT-TGS con indicadores de anomalía.
- **Integración con otros eventos:**  
  - Correlaciona con eventos 4625 (failed logons) para detectar credential stuffing previo.
  - Integra con logs de EDR para detectar herramientas como Mimikatz en endpoints.
  - Cruza con logs de firewall para validar origen de autenticaciones sospechosas.

---

# Golden Ticket: Técnicas de ataque y su detección

1. **Golden Ticket clásico (krbtgt hash)**
   - El atacante extrae el hash de la cuenta krbtgt y forja TGTs arbitrarios.
   - **Detección:** TGTs con lifetime excesivo, encryptación RC4, generación fuera de DCs.

2. **Golden Ticket con SID History**
   - El adversario inyecta SIDs de grupos privilegiados en el ticket forjado.
   - **Detección:** PreAuth types anómalos, accesos a recursos no autorizados para el usuario.

3. **Golden Ticket para persistencia**
   - Uso de Golden Tickets para mantener acceso sin credenciales válidas.
   - **Detección:** Autenticaciones repetidas sin logon events correspondientes, patrones de acceso inusuales.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Empieza siempre por eventos 4768 con análisis de encryption type y origen.**
- Correlaciona con eventos 4769 para detectar patrones de uso de TGT forjados.
- Monitora cuentas privilegiadas y servicios críticos para uso anómalo.
- Implementa detección de herramientas de forging (Mimikatz, Rubeus) en endpoints.
- Considera rotación frecuente de cuenta krbtgt y monitoreo de cambios de hash.
- Valida configuraciones de encriptación y políticas de Kerberos.
- Despliega honeypots y canary tokens para detectar uso de Golden Tickets.

---

## Tabla de Consultas SPL para Hunt for Golden Ticket Detection

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4768 NOT ComputerName IN ("DC01","DC02","DC-PROD*") \| table _time, Account_Name, Client_Address, ComputerName, TicketEncryptionType` | Detecta TGTs generados fuera de controladores de dominio conocidos. |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4769 \| join type=left Account_Name [search EventCode=4768 \| rename _time as tgt_time] \| where isnull(tgt_time) \| table _time, Account_Name, Service_Name` | Identifica solicitudes TGS sin TGT previo válido (Golden Ticket usage). |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4768 TicketEncryptionType="0x17" Account_Name IN ("*admin*","krbtgt","*svc*") \| stats count by Account_Name, Client_Address` | Detecta cuentas privilegiadas usando RC4 encryption en TGTs. |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4768 \| eval lifetime_check=if(match(Ticket_Options,".*0x50810000.*"),"SUSPICIOUS_LIFETIME","NORMAL") \| where lifetime_check="SUSPICIOUS_LIFETIME"` | Identifica TGTs con lifetime anómalo (indicador de Golden Ticket). |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4662 Properties="*1131f6aa*" \| join SubjectLogonId [search EventCode=4768 TicketEncryptionType="0x17"] \| table _time, SubjectUserName, Client_Address` | Detecta DCSync realizado con Golden Tickets (RC4 encryption). |

---

## 🧠 Consejos finales de defensa y hunting

- **Rota la cuenta krbtgt cada 6 meses máximo y monitorea eventos post-rotación.**
- Implementa políticas de Kerberos que fuercen AES encryption y reduzcan lifetime de tickets.
- Despliega herramientas de detección de Golden Ticket como Purple Knight o Pingcastle.
- Automatiza la correlación de eventos 4768/4769 con anomalías de timing y origen.
- Simula ataques Golden Ticket en ejercicios red team para validar detección.
- Considera implementar Kerberos Armoring (FAST) para protección adicional.