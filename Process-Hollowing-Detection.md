# 🛡️ Hunting y Detección de Process Hollowing (T1055.012) y Process Injection

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Procesos creados y modificados inmediatamente (Sysmon Event 1 + 8)**
Busca procesos que son creados y luego modificados via injection en ventanas de tiempo cortas:
- **Logs:** Sysmon EventCode 1 (Process Creation) + EventCode 8 (CreateRemoteThread)
- **Indicador clave:** CreateRemoteThread hacia proceso recién creado

```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rename ProcessId as target_pid, _time as creation_time, Image as target_image
| join target_pid [
    search index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
    | rename TargetProcessId as target_pid, _time as injection_time
    | table target_pid, injection_time, SourceImage, TargetImage, StartFunction
]
| where injection_time > creation_time AND injection_time < (creation_time + 30)
| table creation_time, target_image, target_pid, injection_time, SourceImage, StartFunction
| sort -creation_time
```
- **Revisa:** ¿Procesos legítimos (svchost, explorer) siendo targets de injection inmediatamente tras creación?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Process Hollowing con patrones de memoria sospechosos**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search GrantedAccess="0x1f3fff" OR GrantedAccess="0x1fffff" OR GrantedAccess="0x143a" OR GrantedAccess="0x1410"
| where TargetImage!="" AND SourceImage!=TargetImage
| search (TargetImage="*\\svchost.exe" OR TargetImage="*\\explorer.exe" OR TargetImage="*\\notepad.exe" OR TargetImage="*\\calc.exe")
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| sort -_time
```
- Detecta process access con permisos típicos de hollowing (PROCESS_ALL_ACCESS).

---

### **3. Procesos suspended creados por aplicaciones inusuales**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*CREATE_SUSPENDED*" OR (ParentImage="*\\cmd.exe" AND Image="*\\svchost.exe")
| search NOT ParentImage="*\\services.exe" AND NOT ParentImage="*\\wininit.exe"
| table _time, Computer, Image, ParentImage, CommandLine, User
| sort -_time
```
- Identifica procesos creados en estado suspended por parents no legítimos.

---

### **4. Injection en procesos críticos del sistema**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| search (TargetImage="*\\winlogon.exe" OR TargetImage="*\\csrss.exe" OR TargetImage="*\\smss.exe" OR TargetImage="*\\lsass.exe")
| where SourceImage!=TargetImage
| table _time, Computer, SourceImage, TargetImage, StartFunction, StartModule
| sort -_time
```
- Detecta injection en procesos críticos de Windows.

---

### **5. Análisis de CallTrace para detectar técnicas de injection**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search CallTrace="*ntdll.dll*" AND CallTrace="*kernelbase.dll*"
| where CallTrace LIKE "*unknown*" OR CallTrace LIKE "*UNKNOWN*"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| sort -_time
```
- Identifica call traces sospechosos con módulos unknown (indicativo de injection).

---

### **6. Procesos con discrepancias en rutas de imagen**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval expected_path=case(
    match(Image, ".*svchost\.exe$"), "C:\\Windows\\System32\\svchost.exe",
    match(Image, ".*explorer\.exe$"), "C:\\Windows\\explorer.exe",
    match(Image, ".*notepad\.exe$"), "C:\\Windows\\System32\\notepad.exe",
    1=1, "other"
)
| where expected_path!="other" AND Image!=expected_path
| table _time, Computer, Image, expected_path, ParentImage, CommandLine
| sort -_time
```
- Detecta procesos ejecutándose desde ubicaciones no estándar (possible replacement/hollowing).

---

### **7. Correlación de Image/Process load con injection events**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| search NOT Signed="true"
| rename ProcessId as target_pid, _time as load_time, ImageLoaded as loaded_module
| join target_pid [
    search index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
    | rename TargetProcessId as target_pid, _time as injection_time
    | table target_pid, injection_time, SourceImage
]
| where load_time > injection_time AND load_time < (injection_time + 60)
| table injection_time, target_pid, SourceImage, load_time, loaded_module
| sort -injection_time
```
- Correlaciona injection events con carga de módulos no firmados.

---

### **8. Detección de herramientas de Process Hollowing**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (CommandLine="*hollowing*" OR CommandLine="*injection*" OR CommandLine="*RunPE*" OR CommandLine="*process-injection*" OR Image="*inject*")
| table _time, Computer, Image, CommandLine, ParentImage, User
| sort -_time
```
- Identifica herramientas y techniques conocidas de process injection.

---

### **9. Análisis de procesos con entropy anómala en memoria**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval process_name=replace(Image, ".*\\\\([^\\\\]+)$", "\1")
| search (process_name="svchost.exe" OR process_name="explorer.exe" OR process_name="notepad.exe")
| join ProcessId [
    search index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 GrantedAccess="*1f*"
    | rename TargetProcessId as ProcessId
    | table ProcessId, SourceImage, GrantedAccess
]
| where isnotnull(SourceImage)
| table _time, Computer, Image, ProcessId, SourceImage, GrantedAccess
| sort -_time
```
- Detecta procesos legítimos sendo accessed con permisos de memory manipulation.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  CreateRemoteThread (EventCode 8) hacia proceso creado en los últimos 30 segundos.
- **Alerta 2:**  
  Process access con PROCESS_ALL_ACCESS (0x1f3fff) hacia procesos críticos del sistema.
- **Alerta 3:**  
  Proceso ejecutándose desde ubicación no estándar (possible image replacement).
- **Dashboard:**  
  - Panel de injection events por source y target process.
  - Panel de timeline de creation seguido de injection/access.
  - Panel de call traces sospechosos con módulos unknown.
- **Integración con otros eventos:**  
  - Correlaciona con eventos de file creation para detectar payloads dropped.
  - Integra con network events para identificar C2 communication post-injection.
  - Cruza con PowerShell events para detectar scripts de injection.

---

# Process Hollowing: Técnicas de ataque y su detección

1. **Classic Process Hollowing (T1055.012)**
   - Crear proceso suspended, unmapear memoria original, mapear payload malicioso.
   - **Detección:** Procesos suspended por parents inusuales, injection inmediato post-creation.

2. **Process Doppelgänging (T1055.013)**
   - Uso de NTFS transactions para modificar imagen en disco antes de execution.
   - **Detección:** Procesos ejecutándose desde ubicaciones temporales o inconsistentes.

3. **Module Stomping/Overwriting**
   - Sobreescribir módulos legítimos en memoria con código malicioso.
   - **Detección:** Carga de módulos no firmados post-injection, call traces anómalos.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Configura Sysmon con logging detallado de process access y injection events.**
- Implementa monitoring de procesos críticos con behavioral analysis.
- Despliega EDR solutions con memory scanning y anomaly detection.
- Considera application sandboxing para procesos de alto riesgo.
- Implementa DEP y ASLR en todos los sistemas para dificultar injection.
- Monitorea creación de procesos suspended y accesos de memoria anómalos.
- Educa sobre técnicas de evasion y mantén threat intelligence actualizada.

---

## Tabla de Consultas SPL para Hunt for Process Hollowing

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 \| join ProcessId [search EventCode=8] \| where _time > injection_time-30` | Correlaciona creación de procesos con injection inmediato (process hollowing). |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 GrantedAccess="0x1f3fff" TargetImage="*svchost.exe" \| table _time, SourceImage, TargetImage` | Detecta process access con PROCESS_ALL_ACCESS hacia svchost (hollowing target común). |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 TargetImage="*winlogon.exe" \| table _time, SourceImage, TargetImage, StartFunction` | Identifica injection en procesos críticos como winlogon.exe. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image!="C:\\Windows\\System32\\svchost.exe" Image="*svchost.exe" \| table _time, Image, ParentImage` | Detecta svchost ejecutándose desde ubicaciones no estándar (possible replacement). |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 CallTrace="*unknown*" \| table _time, SourceImage, TargetImage, CallTrace` | Identifica call traces con módulos unknown (indicativo de injection). |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*CREATE_SUSPENDED*" NOT ParentImage="*services.exe" \| table _time, Image, ParentImage` | Detecta procesos creados suspended por parents no legítimos. |

---

## 🧠 Consejos finales de defensa y hunting

- **Implementa Control Flow Integrity (CFI) y Return Flow Guard para proteger contra injection.**
- Despliega memory protection solutions que detecten manipulation de process memory.
- Automatiza análisis de process behavior basado en patterns conocidos de injection.
- Considera implementar Kernel Control Flow Integrity (kCFI) en entornos críticos.
- Simula process hollowing en ejercicios red team para validar detección y response.
- Mantén threat intel sobre nuevas técnicas de process injection y evasion.