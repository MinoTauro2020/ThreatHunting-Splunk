# Splunk – Queries avanzadas con correlaciones directas

---

## 1. Intentos de Pass-the-Hash (PtH) y uso de NTLM

### 🔎 Búsqueda básica
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| stats count by Account_Name, IpAddress, Workstation_Name
```

---

#### 1️⃣ ¿El usuario suele autenticarse desde esa IP/host?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| stats dc(IpAddress) as unique_ips by Account_Name
| where unique_ips > 1
```
- Muestra usuarios que han hecho NTLM desde varias IPs (puedes ajustar el valor).

---

#### 2️⃣ ¿Muchos intentos en poco tiempo (spray/automatización)?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| bin _time span=5m
| stats count by Account_Name, IpAddress, _time
| where count > 5
```
- Usuarios/IPs con más de 5 intentos en 5 minutos.

---

#### 3️⃣ ¿Cuentas privilegiadas desde hosts no administrativos?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| search Account_Name="Administrator" OR Account_Name="Domain Admins" OR Account_Name="admin"
| stats count by Account_Name, IpAddress, Workstation_Name
```
- Busca cuentas privilegiadas (ajusta los nombres según tu entorno).

---

#### 4️⃣ ¿Eventos 4625 (fallidos) seguidos de 4624 (éxito) para el mismo usuario/IP?
```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625) Logon_Type=3 Authentication_Package="NTLM"
| sort 0 _time
| streamstats current=f last(EventCode) as prev_event by Account_Name, IpAddress
| search EventCode=4624 prev_event=4625
| table _time, Account_Name, IpAddress, prev_event, EventCode
```
- Encuentra éxitos precedidos de fallos para mismo usuario/IP.

---

#### 5️⃣ ¿Conexiones a recursos administrativos tras un 4624?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
| join IpAddress, Account_Name [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 (Share_Name="\\ADMIN$" OR Share_Name="\\C$")
    | fields IpAddress, Account_Name, _time as share_time
]
| where share_time >= _time AND share_time < (_time + 300)
| table _time, share_time, Account_Name, IpAddress
```
- Busca acceso a shares admins en los 5 minutos tras autenticación.

---

## 2. Enumeración SMB / Acceso a IPC$ y shares administrativos

### 🔎 Búsqueda básica
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 Share_Name="\\IPC$"
| stats count by Account_Name, IpAddress
```

---

#### 1️⃣ ¿Acceso solo a IPC$ y no a otros shares?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140
| stats values(Share_Name) as shares by Account_Name, IpAddress
| where mvcount(shares)=1 AND shares="\\IPC$"
```
- Usuarios/IPs que solo accedieron a IPC$.

---

#### 2️⃣ ¿Muchos accesos desde la misma IP en poco tiempo?
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140 Share_Name="\\IPC$"
| bin _time span=5m
| stats count by IpAddress, _time
| where count > 10
```
- IPs con más de 10 accesos a IPC$ en 5 minutos.

---

#### 3️⃣ ¿Coincide con intentos de autenticación anómalos (4624/4625) desde la misma IP?
```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625 OR EventCode=5140)
| eval tipo=case(EventCode=4624,"ok",EventCode=4625,"fail",EventCode=5140,"ipc")
| stats count(eval(tipo="ipc")) as ipc, count(eval(tipo="ok")) as ok, count(eval(tipo="fail")) as fail by IpAddress
| where ipc>0 AND (ok>0 OR fail>0)
```
- IPs que hicieron logon y luego accedieron a IPC$.

---

#### 4️⃣ ¿Hay conexiones a 445/139 en los logs de firewall o Sysmon?
- **Firewall:**
```splunk
index=firewall sourcetype=windows_firewall
| rex field=_raw "^\S+\s+\S+\s+\S+\s+(?P<protocol>\S+)\s+(?P<src_ip>\S+)\s+(?P<dest_ip>\S+)\s+(?P<src_port>\d+)\s+(?P<dest_port>\d+)"
| search dest_port=445 OR dest_port=139
| stats count by src_ip, dest_ip, dest_port
```
- **Sysmon:**
```splunk
index=sysmon EventID=3 (DestinationPort=445 OR DestinationPort=139)
| stats count by SourceIp, DestinationIp, DestinationPort
```
- IPs con conexiones de red SMB/NetBIOS.

---

¿Quieres que continúe con correlaciones para el resto de técnicas (AS-REP Roasting, Kerberoasting, lateral movement, brute force, etc.)? Solo dímelo y lo hago igual de detallado.
