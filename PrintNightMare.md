# 🛡️ Hunting y Detección de PrintNightmare (CVE-2021-1675/34527) en Active Directory

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Creación/carga de drivers de impresora sospechosos**
Busca eventos que indiquen la instalación de un nuevo driver de impresora, especialmente fuera de cambios planeados:
- **Log:** Microsoft-Windows-PrintService/Operational  
- **Eventos clave:** 316, 319, 322, 808, 819, 821, 842  
- **DriverName/DriverPath** inusuales, rutas UNC, nombres raros o repetitivos (`Totally Not Malicious`, rutas de red, etc).

```splunk
index=dc_logs sourcetype="WinEventLog:Microsoft-Windows-PrintService/Operational" (EventCode=316 OR EventCode=319 OR EventCode=808 OR EventCode=821)
| table _time, ComputerName, User, DriverName, DriverPath, Param1, Param2
| sort -_time
```
- **Revisa:** ¿Se ha cargado un driver desde ruta UNC o una DLL remota? ¿Nombres de driver extraños o drivers no firmados?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Carga de DLLs inusuales por el proceso spoolsv.exe (Sysmon)**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 Image="*spoolsv.exe"
| where NOT ImageLoaded LIKE "C:\\Windows\\System32\\spool\\drivers\\*"
| table _time, Computer, Image, ImageLoaded, User
| sort -_time
```
- Detecta si spoolsv.exe carga DLLs desde rutas extrañas o de red.

---

### **3. Creación de cuentas locales administrativas sospechosas (payload habitual de exploit)**
```splunk
index=dc_logs sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4728)
| table _time, ComputerName, TargetUserName, SamAccountName, Privileges, SubjectUserName
| sort -_time
```
- El exploit suele crear usuarios como `adm1n` y agregarlos a administradores.

---

### **4. Cambios en impresoras/drivers fuera de horarios habituales**
```splunk
index=dc_logs sourcetype="WinEventLog:Microsoft-Windows-PrintService/Operational" (EventCode=316 OR EventCode=319 OR EventCode=808 OR EventCode=821)
| eval hour=strftime(_time, "%H")
| where hour<7 OR hour>20
| table _time, ComputerName, User, DriverName, DriverPath
| sort -_time
```
- Cambios de drivers fuera de ventana administrativa pueden indicar ataque.

---

### **5. Carga de drivers desde rutas de red (UNC)**
```splunk
index=dc_logs sourcetype="WinEventLog:Microsoft-Windows-PrintService/Operational" (EventCode=316 OR EventCode=319 OR EventCode=808 OR EventCode=821)
| search DriverPath="\\\\*"
| table _time, ComputerName, User, DriverName, DriverPath
| sort -_time
```
- Indicador directo de explotación PrintNightmare.

---

### **6. Correlación con logs de creación de procesos**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*spoolsv.exe"
| table _time, Computer, CommandLine, User
| sort -_time
```
- ¿spoolsv.exe ejecutó procesos hijos (payload persistente)?

---

### **7. Solicitudes SMB inusuales desde DC/servidores a shares no habituales**
```splunk
index=firewall sourcetype="firewall" action=allowed dest_port=445
| search src_ip IN ([lista de DCs/servidores críticos])
| stats count by src_ip, dest_ip, dest_port
| where count > 3
```
- ¿El DC se conecta a shares SMB no autorizados? Sospecha de ataque PrintNightmare.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Creación/carga de driver desde ruta de red o nombre no habitual.
- **Alerta 2:**  
  Creación de usuario local admin en host no autorizado justo después de evento de instalación de driver.
- **Dashboard:**  
  - Panel de drivers de impresora instalados por fecha y host.
  - Panel de actividad del spooler fuera de horario habitual.
  - Panel de correlación: cargas de DLL sospechosas + cambios de cuentas locales.
- **Integración con otros eventos:**  
  - Correlaciona con logs de EDR, Sysmon y eventos de seguridad para entender la cadena de ataque completa.

---

# PrintNightmare: Formas de ataque y su detección

1. **Carga remota de DLL maliciosa como driver**
   - El atacante fuerza la instalación de un “driver” que en realidad es un payload.
   - **Detección:** Eventos de cambio/carga de driver, rutas UNC, cargas de DLL no firmadas.

2. **Persistencia mediante drivers maliciosos**
   - El adversario instala un driver persistente para ejecución como SYSTEM.
   - **Detección:** Cambios de drivers no planificados, correlación con creación de cuentas locales o procesos hijos de spoolsv.exe.

3. **Movimiento lateral por abuso de spooler en red**
   - El atacante salta entre hosts usando el spooler y shares SMB.
   - **Detección:** Conexiones SMB inusuales desde servidores/hosts críticos.

---

## 🛠️ Buenas prácticas de hunting y respuesta

- **Empieza siempre por eventos de instalación/carga de drivers o rutas UNC en PrintService/Operational.**
- Afina por volumen, origen, naming, horarios y correlación con eventos de seguridad.
- Documenta hallazgos y automatiza alertas sobre los patrones anteriores.
- Integra con fuentes externas (EDR, firewall, AD, Sysmon) para enriquecer la investigación.
- Considera deshabilitar el Spooler en DCs y servidores donde no sea necesario.
- Simula PrintNightmare o variantes en ejercicios purple/red para validar defensas y hunting.

---

## Tabla de Consultas SPL para Hunt for PrintNightmare
| **Consulta**                                                                                 | **Propósito**                                                        |
|----------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| index="ad_hunting" source=WinEventLog:Microsoft-Windows-PrintService/Operational (EventCode=316 OR EventCode=319 OR EventCode=808 OR EventCode=821) \| table _time, ComputerName, User, DriverName, DriverPath | Detecta instalaciones/cargas de drivers sospechosos.                 |
| index="ad_hunting" source=WinEventLog:Security (EventCode=4720 OR EventCode=4728) \| table _time, ComputerName, TargetUserName, SamAccountName, Privileges | Detecta creación y privilegios de usuarios locales (payload común).   |
| index="ad_hunting" source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=7 Image="*spoolsv.exe" \| where NOT ImageLoaded LIKE "C:\\Windows\\System32\\spool\\drivers\\*" \| table _time, Computer, ImageLoaded | Carga de DLLs sospechosas por spoolsv.exe.                           |
| index="ad_hunting" source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 ParentImage="*spoolsv.exe" \| table _time, Computer, CommandLine | Ejecución de procesos hijos desde spoolsv.exe (persistencia/abuso).   |
| index="firewall" sourcetype="firewall" action=allowed dest_port=445 src_ip IN ([lista de DCs]) \| stats count by src_ip, dest_ip \| where count > 3 | SMB anómalo desde servidores críticos (movimiento lateral).           |

---

## 🧠 Consejos finales de defensa y hunting

- **Si no necesitas impresión en el host, deshabilita el Spooler.**
- Refuerza con GPOs restrictivas y aplica todos los parches.
- Automatiza la investigación de eventos PrintService/Operational y correlación con cambios de cuentas y procesos.
- Valida tu cobertura con ejercicios purple/red y actualiza tus reglas de hunting regularmente.
