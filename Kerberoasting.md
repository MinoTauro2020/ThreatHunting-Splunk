# 🛡️ Hunting y Detección de Kerberoasting en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Solicitudes de TGS (evento 4769) para cuentas de servicio**
Busca todos los eventos donde se solicitan tickets de servicio Kerberos (TGS), especialmente a cuentas con SPN configurado.  
**Esta es la señal principal de Kerberoasting.**

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| table _time, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type, ComputerName
```
- **Revisa:** ¿Hay varias solicitudes en poco tiempo? ¿Desde la misma IP? ¿A cuentas de servicio sensibles?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Solicitudes repetidas de TGS a varias cuentas desde una misma IP**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| stats count by Client_Address, Service_Name
| where count > 3
```
- IPs que atacan/solicitan hashes de varias cuentas de servicio (patrón clásico de ataque).

---

### **3. Solicitudes a cuentas de servicio privilegiadas o críticas**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*"
| table _time, Service_Name, Account_Name, Client_Address
```
- Atentos si el ataque va contra cuentas críticas o privilegiadas.

---

### **4. Correlación con otros eventos sospechosos del mismo origen**
```splunk
index=dc_logs (sourcetype=WinEventLog:Security AND (EventCode=4769 OR EventCode=4625 OR EventCode=4740))
| search Client_Address="IP_SOSPECHOSA"
| sort _time
```
- Cambia `"IP_SOSPECHOSA"` por el origen detectado.  
- ¿La misma IP provoca fallos de logon o bloqueos?

---

### **5. Solicitudes de TGS con cifrado RC4 (más vulnerables a cracking)**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type=0x17 OR Ticket_Encryption_Type=0x23
| table _time, Service_Name, Account_Name, Client_Address
```
- RC4 es el cifrado más fácil de crackear, muy buscado por atacantes.

---

### **6. Solicitudes desde redes externas o no confiables**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Service_Name, Account_Name, Client_Address
```
- Muy sospechoso: Kerberoasting desde fuera de la red corporativa.

---

### **7. Solicitudes externas mostrando todos los usuarios que han hecho logon antes del 4769**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
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
- ¿La IP ya tenía logons previos legítimos o es nueva en la red?

---

### **8. Analizar ausencia de logons previos por esa IP**
```splunk
... | stats count by kerb_time, kerb_ip | where count=0
```
- Busca IPs externas que solo aparecen en eventos de Kerberoasting.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Si hay más de 3 eventos 4769 hacia diferentes Service_Name desde la misma IP en menos de 1 minuto.
- **Alerta 2:**  
  Si el destino es una cuenta de servicio privilegiada.
- **Dashboard:**  
  - Panel por volumen de 4769 por IP.
  - Panel de cuentas de servicio objetivo más atacadas.
  - Panel de solicitudes de TGS con cifrado RC4.
  - Panel de cambios de SPN y cuentas de servicio (eventos 4738).
- **Integración con otros eventos:**  
  - Correlaciona con eventos 5156/5158 para detectar ráfagas de conexiones.
  - Añade panel de eventos 4625/4740 de la misma IP para ver si hay intentos de acceso o bloqueo.
  - Cruza con logs de firewall para ver accesos externos.

---

# Kerberoasting: Tres formas de ataque y su detección

1. **Con un usuario autenticado del dominio**
   - El atacante tiene acceso a una cuenta válida y la usa para solicitar hashes TGS de cuentas de servicio con SPN.
   - **Detección:** Se observa actividad 4769 anómala desde un usuario legítimo, pero solicitando hashes de otras cuentas de servicio.

2. **Con una lista de cuentas de servicio (SPN) del dominio**
   - El atacante enumera cuentas con SPN por LDAP, PowerView, Impacket, etc.
   - Lanza solicitudes en masa para ver cuáles pueden ser crackeadas.
   - **Detección:** Se detecta una misma IP solicitando hashes para muchos servicios diferentes en poco tiempo.

3. **Sabiendo directamente la cuenta de servicio vulnerable**
   - El atacante conoce exactamente el nombre de la cuenta de servicio objetivo.
   - Ataca solo a esa cuenta de forma puntual y sigilosa.
   - **Detección:** Solicitud aislada de TGS, desde una IP no habitual o externa.

## 🛠️ Buenas prácticas

- **Empieza siempre por el evento 4769.**
- Luego afina y correlaciona: volumen, origen, cuentas críticas, tipo de cifrado, cambios de configuración, y presencia de logons previos.
- Documenta los resultados y automatiza alertas sobre los patrones anteriores.

---
