# 🛡️ Hunting y Detección de AS-REP Roasting en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Solicitudes AS-REQ sin preautenticación (evento 4768, Pre_Authentication_Type=0)**
Busca todas las peticiones AS-REQ donde la cuenta no requiere preautenticación.  
**Esta es la señal principal de AS-REP Roasting.**

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Client_Address, ComputerName
```
- **Revisa:** ¿Hay varias solicitudes en poco tiempo? ¿Desde la misma IP? ¿A cuentas sensibles?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Solicitudes repetidas a varias cuentas desde una misma IP**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| stats count by Client_Address, Account_Name
| where count > 3
```
- IPs que atacan/solicitan hashes de varias cuentas (patrón clásico de ataque).

---

### **3. Solicitudes a cuentas privilegiadas**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search Account_Name="Administrator" OR Account_Name="krbtgt" OR Account_Name="*svc*" OR Account_Name="*admin*"
| table _time, Account_Name, Client_Address
```
- Atentos si el ataque va contra cuentas críticas.

---

### **4. Correlación con otros eventos sospechosos del mismo origen**
```splunk
index=dc_logs (sourcetype=WinEventLog:Security AND (EventCode=4768 OR EventCode=4625 OR EventCode=4740))
| search Client_Address="IP_SOSPECHOSA"
| sort _time
```
- Cambia `"IP_SOSPECHOSA"` por el origen detectado.  
- ¿La misma IP provoca fallos de logon o bloqueos?

---

### **5. Cambios en cuentas (preautenticación deshabilitada recientemente)**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4738
| search "Do not require Kerberos preauthentication"=TRUE
| table _time, Target_Account_Name, ComputerName, Subject_Account_Name
```
- Detectar si alguien ha cambiado la configuración de preautenticación en cuentas.

---

### **6. Solicitudes desde redes externas o no confiables**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Account_Name, Client_Address
```
- Muy sospechoso: AS-REP Roasting desde fuera de la red corporativa.

---

### **7. Solicitudes externas mostrando todos los usuarios que han hecho logon antes del 4768**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| rename Account_Name as asrep_user, Client_Address as asrep_ip, _time as asrep_time
| join asrep_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=asrep_ip AND logon_time < asrep_time
| table asrep_time, asrep_user, asrep_ip, logon_user, logon_time
| sort asrep_time, asrep_ip, logon_time
```
- ¿La IP ya tenía logons previos legítimos o es nueva en la red?

---

### **8. Analizar ausencia de logons previos por esa IP**
```splunk
... | stats count by asrep_time, asrep_ip | where count=0
```
- Busca IPs externas que solo aparecen en eventos de AS-REP Roasting.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Si hay más de 3 eventos 4768 con Pre_Authentication_Type=0 desde la misma IP en menos de 1 minuto.
- **Alerta 2:**  
  Si el destino es una cuenta privilegiada.
- **Dashboard:**  
  - Panel por volumen de 4768 Pre_Authentication_Type=0 por IP.
  - Panel de cuentas objetivo más atacadas.
  - Panel de cambios de configuración de preautenticación (4738).
- **Integración con otros eventos:**  
  - Correlaciona con eventos 5156/5158 para detectar ráfagas de conexiones.
  - Añade panel de eventos 4625/4740 de la misma IP para ver si hay intentos de acceso o bloqueo.
  - Cruza con logs de firewall para ver accesos externos.

---

## 🛠️ Buenas prácticas

- **Empieza siempre por el evento 4768 con Pre_Authentication_Type=0.**
- Luego afina y correlaciona: volumen, origen, cuentas críticas, cambios de config, y presencia de logons previos.
- Documenta los resultados y automatiza alertas sobre los patrones anteriores.

---
