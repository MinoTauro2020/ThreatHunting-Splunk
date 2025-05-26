# 🛡️ Hunting: Detección de Uso de rpcclient (ej: enumdomusers) en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Acceso remoto a share IPC$ (evento 5140)**
El uso de `rpcclient` suele implicar conexión al recurso `\\IPC$`.
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 Share_Name="\\IPC$"
| stats count by Account_Name, IpAddress, ComputerName
```
- Busca accesos desde IPs o cuentas inusuales.

---

### **2. Autenticaciones de red (4624 tipo 3) desde la misma IP**
Enumerar usuarios con `rpcclient` requiere autenticarse en el servicio.
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3
| stats count by Account_Name, IpAddress, Authentication_Package
```
- Filtra por autenticaciones NTLM o Kerberos asociadas a accesos a IPC$.

---

### **3. Conexiones a puertos 445/139 (firewall o Sysmon)**
`rpcclient` usa SMB/RPC para enumerar. Busca actividad de red relacionada:
```splunk
index=firewall sourcetype=windows_firewall
| rex field=_raw "^\S+\s+\S+\s+\S+\s+(?P<protocol>\S+)\s+(?P<src_ip>\S+)\s+(?P<dest_ip>\S+)\s+(?P<src_port>\d+)\s+(?P<dest_port>\d+)"
| search dest_port=445 OR dest_port=139
| stats count by src_ip, dest_ip, dest_port
```
**O con Sysmon:**
```splunk
index=sysmon EventID=3 (DestinationPort=445 OR DestinationPort=139)
| stats count by SourceIp, DestinationIp, DestinationPort
```

---

## 🔎 Afinando la búsqueda y correlación

### **4. ¿Solo acceso a IPC$ y no a otros shares?**
Patrón muy típico de enumeración, no de uso legítimo.
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140
| stats values(Share_Name) as shares by IpAddress
| where mvcount(shares)=1 AND shares="\\IPC$"
```

---

### **5. Ráfaga de accesos o autenticaciones en poco tiempo**
Automatización o ataque suele generar muchos eventos en segundos.
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 Share_Name="\\IPC$"
| bin _time span=1m
| stats count by IpAddress, _time
| where count > 10
```

---

### **6. Coincidencia entre autenticaciones y acceso a IPC$**
¿La misma IP hace logon y accede a IPC$ casi seguidos?
```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=5140)
| eval tipo=case(EventCode=4624,"logon",EventCode=5140,"ipc")
| stats count(eval(tipo="logon")) as logons, count(eval(tipo="ipc")) as ipc by IpAddress
| where logons>0 AND ipc>0
```

---

### **7. Cuentas privilegiadas accediendo a IPC$ desde hosts no habituales**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 Share_Name="\\IPC$"
| search Account_Name="Administrator" OR Account_Name="admin" OR Account_Name="Domain Admins"
| stats count by Account_Name, IpAddress, ComputerName
```

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta:**  
  Si una IP accede a IPC$ más de 10 veces en 1 minuto y no accede a otros shares.
- **Dashboard:**  
  - Panel de IPs con mayor número de accesos a IPC$.
  - Panel de cuentas que más acceden a IPC$.
  - Panel de autenticaciones tipo 3 por IP.
  - Panel de conexiones a puertos 445/139.

---

## 🛠️ Buenas prácticas

- **Empieza siempre por los eventos 5140 a IPC$.**
- Correlaciona con autenticaciones y tráfico a 445/139.
- Prioriza IPs/cuentas que solo acceden a IPC$ y lo hacen en ráfaga.
- Documenta y automatiza alertas sobre estos patrones.

---

