# 🛡️ Hunting y Detección de Registry Persistence Mechanisms (T1547)

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Modificaciones en Run/RunOnce Keys (Boot/Logon Autostart)**
Busca cambios en las claves de registro más comunes para persistencia:
- **Logs:** Sysmon EventCode 13 (Registry Value Set)
- **Indicadores clave:** Modificaciones en HKLM\Software\Microsoft\Windows\CurrentVersion\Run*

```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*" OR TargetObject="*\\RunOnceEx\\*")
| search (TargetObject="*HKLM*" OR TargetObject="*HKCU*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- **Revisa:** ¿Nuevas entradas en Run keys? ¿Executables desde ubicaciones inusuales? ¿Scripts o comandos sospechosos?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Persistence via Windows Services Registry**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Services\\*" AND (TargetObject="*\\ImagePath*" OR TargetObject="*\\Type*" OR TargetObject="*\\Start*")
| where NOT match(Details, ".*Program Files.*") AND NOT match(Details, ".*Windows\\\\System32.*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Detecta modificaciones de servicios con rutas sospechosas o tipos de inicio anómalos.

---

### **3. COM Hijacking via Registry (InprocServer32/LocalServer32)**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\InprocServer32\\*" OR TargetObject="*\\LocalServer32\\*" OR TargetObject="*\\CLSID\\*")
| where NOT match(Details, ".*Program Files.*") AND NOT match(Details, ".*Windows\\\\System32.*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Identifica hijacking de objetos COM para persistence.

---

### **4. Persistence via Shell Extensions y Context Menu**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\ShellExecuteHooks\\*" OR TargetObject="*\\ContextMenuHandlers\\*" OR TargetObject="*\\PropertySheetHandlers\\*" OR TargetObject="*\\ShellIconOverlayIdentifiers\\*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Detecta persistence mediante shell extensions y context menu handlers.

---

### **5. Winlogon Registry Persistence (Userinit, Shell, Notify)**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Winlogon\\*" AND (TargetObject="*Userinit*" OR TargetObject="*Shell*" OR TargetObject="*Notify*" OR TargetObject="*VmApplet*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Identifica modificaciones en Winlogon para persistence en login.

---

### **6. Image File Execution Options (IFEO) Hijacking**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Image File Execution Options\\*" AND TargetObject="*\\Debugger*"
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Detecta IFEO hijacking para persistence/privilege escalation.

---

### **7. App Compatibility Shims Registry Persistence**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\AppCompatFlags\\*" OR TargetObject="*\\InstalledSDB\\*"
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Identifica uso de application compatibility shims para persistence.

---

### **8. Registry persistence en Security/System Keys**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\Authentication Packages*" OR TargetObject="*\\Security Packages*" OR TargetObject="*\\Notification Packages*" OR TargetObject="*\\Lsa\\*")
| table _time, Computer, TargetObject, Details, Image, User
| sort -_time
```
- Detecta modificaciones en LSA/Security packages para persistence privilegiada.

---

### **9. Correlación de Registry changes con Process creation**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search TargetObject="*\\Run\\*"
| eval registry_time=_time, registry_value=Details
| rename Image as registry_modifier
| join registry_value [
    search index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    | eval process_time=_time
    | eval match_result=if(match(CommandLine, ".*"+registry_value+".*"), "MATCH", "NO_MATCH")
    | where match_result="MATCH"
    | table process_time, Image, CommandLine, registry_value
]
| where process_time > registry_time
| table registry_time, TargetObject, registry_value, process_time, Image, CommandLine
| sort -registry_time
```
- Correlaciona cambios de registro con ejecución subsecuente de los executables registrados.

---

### **10. Registry Keys modificados por procesos no estándar**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\Run\\*" OR TargetObject="*\\Services\\*" OR TargetObject="*\\Winlogon\\*")
| where NOT (Image="C:\\Windows\\System32\\reg.exe" OR Image="*\\regedit.exe" OR Image="*\\RegEdit.exe" OR match(Image, ".*Program Files.*"))
| table _time, Computer, Image, TargetObject, Details, User
| sort -_time
```
- Identifica modificaciones de registry por procesos no administrativos o sospechosos.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Modificación de Run/RunOnce keys con executables desde ubicaciones no estándar.
- **Alerta 2:**  
  Cambios en Winlogon registry keys (Userinit, Shell, Notify) por procesos no autorizados.
- **Alerta 3:**  
  Modificación de Service ImagePath hacia executables fuera de Program Files o System32.
- **Dashboard:**  
  - Panel de modificaciones de registry por tipo de persistence mechanism.
  - Panel de timeline de registry changes correlacionados con process execution.
  - Panel de top persistence locations y frecuencia de uso.
- **Integración con otros eventos:**  
  - Correlaciona con file creation events para detectar payloads dropped.
  - Integra con logon events para validation de persistence effectiveness.
  - Cruza con network events para identificar C2 communication post-persistence.

---

# Registry Persistence: Técnicas de ataque y su detección

1. **Registry Run Keys (T1547.001)**
   - Modificación de HKLM/HKCU Run keys para autostart en login/boot.
   - **Detección:** EventCode 13 en Run/RunOnce keys, especialmente con rutas inusuales.

2. **Windows Service Registry (T1543.003)**
   - Creación/modificación de servicios via registry para persistence privilegiada.
   - **Detección:** Cambios en Services registry key con ImagePath sospechosos.

3. **COM Object Hijacking (T1546.015)**
   - Hijacking de CLSID/ProgID para execution cuando aplicaciones usan COM objects.
   - **Detección:** Modificaciones en InprocServer32/LocalServer32 keys.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Implementa monitoring comprehensivo de registry changes en keys críticos.**
- Despliega baseline de registry configurations para detectar deviations.
- Considera registry protection solutions y access control restrictivo.
- Implementa periodic scanning de persistence mechanisms conocidos.
- Educa sobre técnicas de registry persistence y mantén threat intel actualizada.
- Correlaciona registry changes con otros artifacts (files, processes, network).
- Simula registry persistence en ejercicios para validar detection coverage.

---

## Tabla de Consultas SPL para Hunt for Registry Persistence

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Run\\*" \| table _time, Computer, TargetObject, Details, Image` | Detecta modificaciones en Run keys para autostart persistence. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Services\\*ImagePath*" NOT Details="*Program Files*" \| table _time, TargetObject, Details` | Identifica servicios con ImagePath sospechosos fuera de ubicaciones estándar. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Winlogon\\*" \| table _time, Computer, TargetObject, Details, User` | Detecta modificaciones en Winlogon keys para login persistence. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\InprocServer32\\*" NOT Details="*System32*" \| table _time, TargetObject, Details` | Identifica COM hijacking via InprocServer32 modifications. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Image File Execution Options\\*\\Debugger*" \| table _time, TargetObject, Details` | Detecta IFEO hijacking para persistence/privilege escalation. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Authentication Packages*" \| table _time, Computer, TargetObject, Details, Image` | Identifica modificaciones en LSA Authentication Packages. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\ShellExecuteHooks\\*" \| table _time, Computer, TargetObject, Details` | Detecta persistence via Shell Execute Hooks. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\AppCompatFlags\\*" \| table _time, Computer, TargetObject, Details, Image` | Identifica uso de App Compatibility Shims para persistence. |

---

## 🧠 Consejos finales de defensa y hunting

- **Implementa Group Policy restrictions en registry keys críticos para persistence.**
- Despliega registry auditing granular y real-time monitoring solutions.
- Considera registry backup y restore procedures para incident response.
- Automatiza detection de persistence mechanisms con scheduled searches.
- Mantén inventory de legitimate software que modifica registry para whitelist.
- Simula registry persistence attacks para validation de detection y response capabilities.