# 🛡️ Hunting y Detección de Living Off The Land Binaries (LOLBins) Abuse

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Uso anómalo de binarios legítimos de Windows para ejecución de código**
Busca binarios de Windows utilizados de manera no convencional para ejecutar código arbitrario:
- **Logs:** Sysmon EventCode 1 (Process Creation)
- **Indicadores clave:** Líneas de comando inusuales, parámetros de red, execución desde ubicaciones extrañas

```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| where (match(CommandLine, ".*http[s]?://.*") OR match(CommandLine, ".*\\.ps1.*") OR match(CommandLine, ".*\\.vbs.*") OR match(CommandLine, ".*\\.hta.*"))
| table _time, Computer, Image, CommandLine, ParentImage, User
| sort -_time
```
- **Revisa:** ¿Binarios ejecutándose con parámetros de red? ¿Scripts descargados o ejecutados desde ubicaciones inusuales?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Regsvr32.exe con conexiones de red (Squiblydoo technique)**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\regsvr32.exe" AND (CommandLine="*/i:http*" OR CommandLine="*/u*" OR CommandLine="*scrobj.dll*")
| table _time, Computer, CommandLine, ParentImage, ProcessId
| sort -_time
```
- Detecta technique T1218.010 - Regsvr32 para ejecutar código remoto.

---

### **3. Rundll32.exe ejecutando funciones sospechosas**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\rundll32.exe"
| where (match(CommandLine, ".*javascript:.*") OR match(CommandLine, ".*DllRegisterServer.*") OR match(CommandLine, ".*DllInstall.*") OR match(CommandLine, ".*url\\.dll.*") OR match(CommandLine, ".*shell32.*ShellExec.*"))
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Identifica uso de rundll32 para ejecutar JavaScript, funciones DLL peligrosas o bypass de UAC.

---

### **4. Certutil.exe para descargas y decodificación**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\certutil.exe"
| where (match(CommandLine, ".*-urlcache.*") OR match(CommandLine, ".*-decode.*") OR match(CommandLine, ".*-f.*") OR match(CommandLine, ".*http[s]?://.*"))
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Detecta certutil usado para descargar archivos o decodificar payloads.

---

### **5. MSHTA.exe ejecutando contenido remoto**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\mshta.exe"
| where (match(CommandLine, ".*http[s]?://.*") OR match(CommandLine, ".*\\.hta.*") OR match(CommandLine, ".*javascript:.*") OR match(CommandLine, ".*vbscript:.*"))
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Identifica mshta ejecutando HTML Applications remotas o scripts embebidos.

---

### **6. Bitsadmin para transferencias de archivos sospechosas**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\bitsadmin.exe"
| where (match(CommandLine, ".*\\/transfer.*") OR match(CommandLine, ".*\\/download.*") OR match(CommandLine, ".*http[s]?://.*"))
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Detecta uso de bitsadmin para descargar archivos maliciosos.

---

### **7. InstallUtil.exe para ejecución de .NET assemblies**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\InstallUtil.exe"
| where NOT (match(CommandLine, ".*Microsoft\\.NET.*") OR match(CommandLine, ".*Program Files.*"))
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Identifica InstallUtil ejecutando assemblies desde ubicaciones no estándar.

---

### **8. MSBuild.exe para compilación y ejecución inline**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\MSBuild.exe"
| where NOT ParentImage="*\\devenv.exe" AND NOT ParentImage="*\\VisualStudio.*"
| table _time, Computer, CommandLine, ParentImage, User
| sort -_time
```
- Detecta MSBuild usado fuera de entornos de desarrollo legítimos.

---

### **9. Correlación de LOLBins con conexiones de red**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| rename ProcessId as proc_id, _time as exec_time
| join proc_id [
    search index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
    | rename ProcessId as proc_id, _time as conn_time
    | table proc_id, conn_time, DestinationIp, DestinationPort
]
| where conn_time >= exec_time AND conn_time <= (exec_time + 300)
| table exec_time, Computer, Image, CommandLine, DestinationIp, DestinationPort
| sort -exec_time
```
- Correlaciona ejecución de LOLBins con conexiones de red subsecuentes.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Ejecución de regsvr32.exe, rundll32.exe, o mshta.exe con parámetros de URLs remotas.
- **Alerta 2:**  
  Certutil.exe usado con flags -urlcache, -decode, o -f fuera de horarios administrativos.
- **Alerta 3:**  
  Cualquier LOLBin ejecutado desde directorios de usuarios o ubicaciones temporales.
- **Dashboard:**  
  - Panel de top LOLBins ejecutados por host y usuario.
  - Panel de timeline de ejecución de LOLBins con correlación de red.
  - Panel de análisis de líneas de comando para detección de patrones.
- **Integración con otros eventos:**  
  - Correlaciona con eventos de file creation (EventCode 11) para detectar payloads descargados.
  - Integra con DNS logs para identificar dominios maliciosos contactados.
  - Cruza con process injection events (EventCode 8) para detectar técnicas avanzadas.

---

# LOLBins: Técnicas de abuso y su detección

1. **Download and Execute (T1105)**
   - Uso de certutil, bitsadmin, o PowerShell para descargar y ejecutar payloads.
   - **Detección:** Parámetros de red en líneas de comando, correlación con conexiones HTTP/HTTPS.

2. **Bypass Application Whitelisting (T1218)**
   - Regsvr32, rundll32, mshta para ejecutar código no firmado o remoto.
   - **Detección:** Parámetros inusuales, ejecución desde ubicaciones no estándar.

3. **Code Execution via Trusted Process (T1127)**
   - MSBuild, InstallUtil para ejecutar .NET code inline.
   - **Detección:** Ejecución fuera de contextos de desarrollo, análisis de assemblies.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Monitorea LOLBins con análisis de líneas de comando y contexto de ejecución.**
- Implementa whitelist de parámetros legítimos para binarios comúnmente abusados.
- Correlaciona ejecución de LOLBins con actividad de red y file system.
- Despliega Application Control/WDAC para restringir ejecución no autorizada.
- Considera block de parámetros peligrosos en proxies/firewalls.
- Educa a usuarios sobre técnicas de social engineering que abusan LOLBins.
- Automatiza detección con machine learning para identificar nuevos patrones.

---

## Tabla de Consultas SPL para Hunt for LOLBins Abuse

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\regsvr32.exe" CommandLine="*/i:http*" \| table _time, Computer, CommandLine, User` | Detecta Squiblydoo technique - regsvr32 ejecutando scriptlets remotos. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\certutil.exe" CommandLine="*-urlcache*" \| table _time, Computer, CommandLine, ParentImage` | Identifica certutil usado para descargar archivos desde URLs. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\mshta.exe" CommandLine="*http*" \| table _time, Computer, CommandLine, User` | Detecta mshta ejecutando HTML Applications remotas. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\rundll32.exe" CommandLine="*javascript:*" \| table _time, Computer, CommandLine, ParentImage` | Identifica rundll32 ejecutando JavaScript para bypass. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\InstallUtil.exe" NOT CommandLine="*Microsoft.NET*" \| table _time, Computer, CommandLine, User` | Detecta InstallUtil ejecutando assemblies no estándar. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\MSBuild.exe" NOT ParentImage="*devenv*" \| table _time, Computer, CommandLine, ParentImage` | Identifica MSBuild usado fuera de desarrollo legítimo. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe") \| where match(CommandLine,".*\\\\.+\\\\.+\\\\.*") \| table _time, Computer, Image, CommandLine` | Detecta LOLBins ejecutando desde rutas UNC o directorios remotos. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\bitsadmin.exe" CommandLine="*/transfer*" \| table _time, Computer, CommandLine, User` | Identifica bitsadmin usado para transferencias de archivos. |

---

## 🧠 Consejos finales de defensa y hunting

- **Implementa Application Control para restringir ejecución de LOLBins con parámetros peligrosos.**
- Despliega rules de proxy/firewall para block URLs conocidas en parámetros de LOLBins.
- Automatiza análisis de líneas de comando con regex patterns y machine learning.
- Considera renaming o restricción de LOLBins no críticos en endpoints.
- Simula ataques LOLBins en ejercicios red team para validar detección y respuesta.
- Mantén threat intelligence actualizada sobre nuevas técnicas LOLBins.