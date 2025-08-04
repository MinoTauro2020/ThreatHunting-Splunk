# eCTHPv2 Hunt 1: Análisis Exhaustivo de MAMABEAR - Guía Completa para Splunk

## Resumen Ejecutivo

El reporte documenta una campaña de ataque dirigida contra ELS Bank, donde el grupo MamaBear comprometió sistemas mediante técnicas avanzadas. Esta guía proporciona consultas Splunk específicas y metodología de caza para identificar todas las fases del ataque MAMABEAR como parte del examen eCTHPv2 Hunt 1.

**Puntos Objetivo**: 40 puntos
**Herramienta**: Splunk SIEM (http://172.16.85.103:8000)
**Credenciales**: admin / eLSHunter

## Acceso al Entorno de Examen

### Configuración Inicial
1. Conectar a VPN del examen
2. Verificar conectividad: `ping 172.16.85.103`
3. Acceder a Splunk: http://172.16.85.103:8000
4. Login: admin / eLSHunter
5. Verificar índices disponibles en Settings -> Indexes

## Metodología de Caza eCTHPv2 Hunt 1

### Objetivos del Examen
- **Evidenciar compromiso completo** del ciclo de ataque (Cyber Kill Chain)
- **Utilizar todos los índices disponibles** en Splunk
- **Documentar cada fase** con consultas SPL específicas
- **Identificar todos los endpoints/servidores** afectados
- **Proporcionar evidencia técnica** detallada con capturas de pantalla

### Fases de Investigación Requeridas
1. **Initial Access** - Vector de compromiso inicial
2. **Attack Vectors/Payloads** - Herramientas y cargas maliciosas utilizadas
3. **Enumeration** - Reconocimiento interno realizado
4. **Lateral Movement** - Movimiento entre sistemas
5. **Privilege Escalation** - Escalada de privilegios
6. **Persistence** - Mecanismos de persistencia
7. **Exfiltration/Impact** - Datos comprometidos o impacto

## Consultas Splunk por Fase de Ataque

### FASE 1: Initial Access (Compromiso Inicial)

#### Investigación de Archivos con ADS (Alternate Data Streams)
**Técnica**: Detección de flujos de datos alternativos utilizados para evasión

```spl
index=* earliest=-30d@d latest=now
| search EventCode=15 OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15
| eval suspicious_ads=if(match(TargetFilename,".*:.*"), "ADS_Detected", "Normal")
| where suspicious_ads="ADS_Detected"
| eval file_location=case(
    match(TargetFilename,".*\\\\Users\\\\.*"), "User_Directory",
    match(TargetFilename,".*\\\\Public\\\\.*"), "Public_Directory", 
    match(TargetFilename,".*\\\\Temp\\\\.*"), "Temp_Directory",
    1==1, "Other"
)
| stats count by Computer, TargetFilename, Image, file_location, suspicious_ads
| sort -count
```

#### Detección de Shell Compiler (shc) y Herramientas de Ofuscación
```spl
index=* earliest=-30d@d latest=now
| search (Image="*shc*" OR CommandLine="*shc*" OR OriginalFileName="*shc*")
| eval suspicious_activity="Shell_Compiler_Usage"
| table _time, Computer, User, Image, CommandLine, ParentImage, suspicious_activity
| sort -_time
```

#### Análisis de Archivos Creados en Ubicaciones Sospechosas
```spl
index=* earliest=-30d@d latest=now
| search EventCode=11
| eval suspicious_location=case(
    match(TargetFilename,".*\\\\marry\\\\.*"), "User_Marry",
    match(TargetFilename,".*\\\\Public\\\\.*"), "Public_Folder",
    match(TargetFilename,".*\\\\Temp\\\\.*"), "Temp_Folder",
    1==1, "Other"
)
| where suspicious_location!="Other"
| stats count by Computer, TargetFilename, Image, suspicious_location
| sort -count
```

### FASE 2: Attack Vectors/Payloads

#### Detección de Windows Script Host (wscript.exe)
```spl
index=* earliest=-30d@d latest=now
| search (Image="*wscript.exe*" OR Image="*cscript.exe*")
| eval script_location=case(
    match(CommandLine,".*\\\\Public\\\\.*"), "Public_Execution",
    match(CommandLine,".*\\.vbs"), "VBS_Script",
    match(CommandLine,".*\\.js"), "JavaScript",
    1==1, "Other_Script"
)
| table _time, Computer, User, Image, CommandLine, ParentImage, script_location
| sort -_time
```

#### Análisis de Persistencia mediante Scripts
```spl
index=* earliest=-30d@d latest=now
| search (Image="*wscript.exe*" OR Image="*cscript.exe*")
| join Computer [
    search index=* earliest=-30d@d latest=now EventCode=13
    | eval persistence_check=if(match(TargetObject,".*\\\\Run\\\\.*"), "Registry_Persistence", "File_Persistence")
]
| table _time, Computer, Image, CommandLine, persistence_check
| sort -_time
```

### FASE 3: Command and Control (C2)

#### Detección de Conexiones Maliciosas
```spl
index=* earliest=-30d@d latest=now
| search EventCode=3 OR sourcetype="stream:tcp" OR sourcetype="firewall"
| eval internal_ip=if(cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip), "Internal", "External")
| eval dest_internal=if(cidrmatch("192.168.0.0/16", dest_ip) OR cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip), "Internal", "External")
| where internal_ip="Internal" AND dest_internal="External"
| eval suspicious_port=case(
    dest_port=80, "HTTP_C2",
    dest_port=443, "HTTPS_C2",
    dest_port=8080, "Alt_HTTP",
    dest_port>=1024 AND dest_port<=65535, "High_Port",
    1==1, "Standard_Port"
)
| stats count by src_ip, dest_ip, dest_port, suspicious_port, Image
| sort -count
```

#### Análisis de Descargas Post-Compromiso
```spl
index=* earliest=-30d@d latest=now
| search (EventCode=11 AND (TargetFilename="*.exe" OR TargetFilename="*.dll"))
| join Computer [
    search index=* earliest=-30d@d latest=now EventCode=3
    | eval download_activity=if(dest_port=80 OR dest_port=443, "Web_Download", "Other")
]
| table _time, Computer, TargetFilename, src_ip, dest_ip, dest_port, download_activity
| sort -_time
```

### FASE 4: Enumeration (Reconocimiento)

#### Detección de Herramientas de Reconocimiento
```spl
index=* earliest=-30d@d latest=now
| search (Image="*whoami.exe*" OR Image="*ipconfig.exe*" OR Image="*net.exe*" OR CommandLine="*SharpHound*" OR CommandLine="*BloodHound*")
| eval recon_type=case(
    match(Image,".*whoami.*"), "User_Enumeration",
    match(Image,".*ipconfig.*"), "Network_Discovery",
    match(CommandLine,".*net user.*"), "User_Discovery",
    match(CommandLine,".*net group.*"), "Group_Discovery",
    match(CommandLine,".*SharpHound.*"), "AD_Enumeration",
    1==1, "General_Recon"
)
| table _time, Computer, User, Image, CommandLine, recon_type
| sort -_time
```

#### Active Directory Enumeration Analysis
```spl
index=* earliest=-30d@d latest=now
| search (CommandLine="*SharpHound*" OR Image="*SharpHound*")
| eval ad_enum_activity=case(
    match(CommandLine,".*-c All.*"), "Complete_AD_Enum",
    match(CommandLine,".*-c DCOnly.*"), "DC_Only_Enum",
    match(CommandLine,".*-c Session.*"), "Session_Enum",
    1==1, "Custom_AD_Enum"
)
| table _time, Computer, User, Image, CommandLine, ad_enum_activity
| sort -_time
```

### FASE 5: Privilege Escalation (Escalada de Privilegios)

#### Detección de Búsqueda de Credenciales
```spl
index=* earliest=-30d@d latest=now
| search (Image="*findstr.exe*" AND (CommandLine="*password*" OR CommandLine="*credential*" OR CommandLine="*login*" OR CommandLine="*cred*"))
| eval cred_search_location=case(
    match(CommandLine,".*sysvol.*"), "SYSVOL_Search",
    match(CommandLine,".*netlogon.*"), "NETLOGON_Search",
    match(CommandLine,".*scripts.*"), "Scripts_Search",
    1==1, "General_Search"
)
| table _time, Computer, User, Image, CommandLine, cred_search_location
| sort -_time
```

#### Análisis de Acceso a SYSVOL
```spl
index=* earliest=-30d@d latest=now
| search (TargetFilename="*sysvol*" OR SourceFilename="*sysvol*")
| eval sysvol_activity=case(
    EventCode=11, "File_Created",
    EventCode=2, "File_Access",
    EventCode=15, "ADS_Created",
    1==1, "Other_Activity"
)
| table _time, Computer, User, Image, TargetFilename, sysvol_activity
| sort -_time
```

### FASE 6: Lateral Movement (Movimiento Lateral)

#### Detección de Transferencia de Archivos Maliciosos
```spl
index=* earliest=-30d@d latest=now
| search (EventCode=5145 OR EventCode=5140)
| eval file_transfer=case(
    match(RelativeTargetName,".*\\.exe$"), "Executable_Transfer",
    match(RelativeTargetName,".*\\.dll$"), "Library_Transfer",
    match(RelativeTargetName,".*\\.bat$"), "Script_Transfer",
    1==1, "Other_Transfer"
)
| where file_transfer!="Other_Transfer"
| table _time, Computer, src_user, RelativeTargetName, file_transfer, ShareName
| sort -_time
```

#### Análisis de Servidores Comprometidos
```spl
index=* earliest=-30d@d latest=now
| search (Computer="*Azure-Sync*" OR dest_host="*Azure-Sync*" OR ComputerName="*Azure-Sync*")
| eval azure_sync_activity=case(
    EventCode=11, "File_Creation",
    EventCode=1, "Process_Execution", 
    EventCode=3, "Network_Connection",
    EventCode=7045, "Service_Install",
    1==1, "Other_Activity"
)
| table _time, Computer, User, Image, CommandLine, azure_sync_activity
| sort -_time
```

#### Detección de Creación de Servicios
```spl
index=* earliest=-30d@d latest=now
| search (EventCode=7045 OR EventCode=4697)
| eval service_analysis=case(
    match(ServiceFileName,".*\\.exe"), "Executable_Service",
    match(ServiceName,".*temp.*"), "Temporary_Service",
    match(ServiceName,".*update.*"), "Update_Service",
    1==1, "Standard_Service"
)
| table _time, Computer, ServiceName, ServiceFileName, service_analysis
| sort -_time
```

### FASE 7: Evasion and Execution

#### Detección de rundll32.exe Abuse
```spl
index=* earliest=-30d@d latest=now
| search Image="*rundll32.exe*"
| eval rundll32_abuse=case(
    match(CommandLine,".*,.*"), "DLL_Function_Call",
    CommandLine="rundll32.exe", "Suspicious_No_Args",
    match(CommandLine,".*javascript:.*"), "JavaScript_Execution",
    1==1, "Standard_Usage"
)
| where rundll32_abuse!="Standard_Usage"
| table _time, Computer, User, Image, CommandLine, ParentImage, rundll32_abuse
| sort -_time
```

#### Análisis de Ejecución desde Memoria
```spl
index=* earliest=-30d@d latest=now
| search (Image="*rundll32.exe*" AND EventCode=1)
| join Computer [
    search index=* earliest=-30d@d latest=now EventCode=8
    | eval memory_activity="Memory_Access"
]
| table _time, Computer, Image, CommandLine, memory_activity
| sort -_time
```

## Timeline Correlation y Análisis Completo

### Correlación Temporal de Eventos
```spl
index=* earliest=-30d@d latest=now
| eval attack_phase=case(
    EventCode=15 AND match(TargetFilename,".*:.*"), "1_Initial_Access_ADS",
    Image="*wscript.exe*", "2_Persistence_VBS",
    EventCode=3 AND dest_port=80, "3_C2_Communication",
    Image="*whoami.exe*" OR Image="*ipconfig.exe*" OR CommandLine="*SharpHound*", "4_Enumeration",
    Image="*findstr.exe*" AND match(CommandLine,".*sysvol.*"), "5_Privilege_Escalation",
    EventCode=5145 AND match(RelativeTargetName,".*\\.exe$"), "6_Lateral_Movement",
    Image="*rundll32.exe*", "7_Evasion_Execution",
    1==1, "Other"
)
| where attack_phase!="Other"
| table _time, Computer, attack_phase, User, Image, CommandLine
| sort _time
```

### Análisis de Sistemas Comprometidos
```spl
index=* earliest=-30d@d latest=now
| search (Computer="*ELSBANK*" OR Computer="*Azure-Sync*" OR Computer="*marry*")
| eval system_role=case(
    match(Computer,".*ELSBANK.*"), "Domain_Controller",
    match(Computer,".*Azure-Sync.*"), "Sync_Server", 
    match(Computer,".*marry.*"), "User_Workstation",
    1==1, "Unknown_System"
)
| stats count by Computer, system_role, User
| sort -count
```

### Identificación de IOCs (Indicators of Compromise)
```spl
index=* earliest=-30d@d latest=now
| eval ioc_type=case(
    match(TargetFilename,".*be6d586\\.exe.*"), "Backdoor_File",
    src_ip="192.168.10.220" OR dest_ip="192.168.10.220", "C2_IP_Address",
    match(CommandLine,".*SharpHound.*"), "AD_Enum_Tool",
    Image="*wscript.exe*" AND match(CommandLine,".*Public.*"), "Persistence_Script",
    1==1, "Other"
)
| where ioc_type!="Other"
| stats count by ioc_type, Computer, Image, CommandLine
| sort -count
```

## Documentación para el Examen eCTHPv2

### Evidencias Requeridas para Hunt 1 (40 Puntos)

#### Checklist de Evidencias Críticas
- [ ] **Vector de Acceso Inicial**: ADS creation (EventCode=15) con screenshot
- [ ] **Persistencia**: VBS execution con consulta SPL y screenshot
- [ ] **C2 Communications**: Conexiones a 192.168.10.220:80 con evidencia
- [ ] **Enumeración**: SharpHound execution con comandos específicos
- [ ] **Escalada de Privilegios**: findstr en sysvol con credenciales encontradas
- [ ] **Movimiento Lateral**: Transferencia de be6d586.exe a Azure-Sync
- [ ] **Evasión**: rundll32.exe execution desde memoria
- [ ] **Timeline Completo**: Secuencia temporal de todos los eventos

#### Formato de Documentación Requerido
```markdown
| Fase de Ataque | Consulta SPL | Evidencia Encontrada | Screenshot |
|----------------|--------------|---------------------|------------|
| Initial Access | [SPL Query] | [Findings] | [Screenshot] |
| Persistence | [SPL Query] | [Findings] | [Screenshot] |
| C2 | [SPL Query] | [Findings] | [Screenshot] |
| Enumeration | [SPL Query] | [Findings] | [Screenshot] |
| Privilege Escalation | [SPL Query] | [Findings] | [Screenshot] |
| Lateral Movement | [SPL Query] | [Findings] | [Screenshot] |
| Evasion | [SPL Query] | [Findings] | [Screenshot] |
```

### Consultas de Validación Final

#### Verificación de Compromiso Completo
```spl
index=* earliest=-30d@d latest=now
| eval mamabear_indicator=case(
    EventCode=15 AND match(TargetFilename,".*:.*"), 1,
    Image="*wscript.exe*" AND match(CommandLine,".*Public.*"), 1,
    dest_ip="192.168.10.220", 1,
    CommandLine="*SharpHound*", 1,
    Image="*findstr.exe*" AND match(CommandLine,".*sysvol.*"), 1,
    match(TargetFilename,".*be6d586\\.exe.*"), 1,
    Image="*rundll32.exe*", 1,
    1==1, 0
)
| where mamabear_indicator=1
| stats count by Computer
| eval compromised=if(count>=3, "CONFIRMED_COMPROMISE", "PARTIAL_INDICATORS")
| table Computer, count, compromised
| sort -count
```

#### Resumen Ejecutivo para Reporte
```spl
index=* earliest=-30d@d latest=now
| eval attack_evidence=case(
    EventCode=15, "Initial_Access_ADS",
    Image="*wscript.exe*", "VBS_Persistence", 
    dest_ip="192.168.10.220", "C2_Communication",
    CommandLine="*SharpHound*", "AD_Enumeration",
    match(CommandLine,".*sysvol.*"), "Credential_Theft",
    match(TargetFilename,".*be6d586.*"), "Backdoor_Deployment",
    Image="*rundll32.exe*", "Memory_Execution",
    1==1, "Other"
)
| where attack_evidence!="Other"
| stats count by attack_evidence, Computer
| eval status="DETECTED"
| table attack_evidence, Computer, count, status
```

## Recomendaciones de Mitigación

| Fase | Acción Correctiva |
|------|------------------|
| **Persistencia** | Bloquear ejecución de scripts VBS desde C:\Users\Public via GPO. |
| **Enumeración** | Monitorear uso de herramientas como SharpHound (comportamiento anómalo de cuentas). |
| **Escalada Privilegios** | Auditar y eliminar archivos con credenciales en texto plano en sysvol. |
| **Movimiento Lateral** | Implementar segmentación de red (VLANS, firewalls internos). |
| **Ejecución** | Restringir uso de rundll32.exe mediante políticas de aplicación whitelisting. |
| **Detección** | Crear reglas Splunk para:<br/>- Eventos Sysmon ID 15 + rutas sospechosas.<br/>- Conexiones salientes al puerto 80 desde servidores internos. |

## Conclusión

El ataque MamaBear explotó múltiples fallos en la postura de seguridad de ELS Bank:

1. **Configuraciones deficientes** (credenciales en texto plano).
2. **Monitoreo insuficiente** (ausencia de detección de TTPs iniciales).
3. **Controles de red ausentes** (movimiento lateral sin restricciones).

**Acción urgente:** Aislar el servidor Azure-Sync, resetear credenciales de dominio, y auditar Sysvol.