# Análisis Exhaustivo del Reporte de Caza de Amenazas "MAMABEAR"

## Resumen Ejecutivo

El reporte documenta una campaña de ataque dirigida contra ELS Bank, donde el grupo MamaBear comprometió sistemas mediante técnicas avanzadas. La investigación se realizó usando Splunk SIEM y detalla 7 etapas del ciclo de vida del ataque, desde infección inicial hasta movimiento lateral.

## TTPs (Tácticas, Técnicas y Procedimientos) Detallados

### 1. Compromiso Inicial

**Indicador Clave:**
- Evento Sysmon ID 15 (File stream create).
- Archivo con flujo de datos alternativo (ADS) generado por shc (Shell Compiler), usado para ofuscar scripts.

**Ubicación:**
- Ruta: `\\ELSBANK\marry\[...]` (cuenta de usuario comprometida).

**Implicación:**
- Técnica de defensa evasiva para ocultar malware en flujos NTFS.

### 2. Persistencia

**Mecanismo:**
- Script VBS ejecutado mediante wscript.exe (Windows Script Host).

**Ubicación:**
- `C:\Users\Public\...` (ruta accesible para evadir sospechas).

**Frecuencia:**
- Ejecución diaria (persistencia garantizada).

### 3. Comando y Control (C2)

**Conexión Maliciosa:**
- IP del atacante: 192.168.10.220 (red interna comprometida).
- Puerto: 80 (tráfico HTTP enmascarado como legítimo).

**Acción Tras Conexión:**
- Descarga/ejecución de payloads adicionales.

### 4. Enumeración

**Herramientas Ejecutadas:**
- `whoami`: Identificación de usuario/privilegios.
- `ipconfig`: Mapeo de red interna.
- `SharpHound`: Recolección de datos de Active Directory (cuentas, grupos, relaciones de confianza).

**Objetivo:**
- Identificar cuentas de dominio con privilegios elevados.

### 5. Escalada de Privilegios

**Técnica:**
- Búsqueda de credenciales en texto claro usando `findstr` (utilidad nativa de Windows).

**Ubicación Comprometida:**
- `\\elsbank\sysvol\elsbank.prod\[...]` (repositorio crítico de políticas de dominio).

**Resultado:**
- Credenciales de dominio expuestas en archivos no cifrados.

### 6. Movimiento Lateral

**Destino:**
- Servidor Azure-Sync (IP: 192.168.10.[...]).

**Acciones:**
- Descarga del backdoor `be6d586.exe`.
- Creación de servicio Windows para persistencia.

**Impacto:**
- Control total sobre servidor crítico de sincronización Azure/AD.

### 7. Ejecución en Azure-Sync

**Técnica de Evasión:**
- Uso de `rundll32.exe` como proxy de ejecución (ejecuta código malicioso desde memoria).

**Finalidad:**
- Evitar detección por firmas de antivirus.

## Hallazgos Críticos y Vulnerabilidades Explotadas

### Almacenamiento de Credenciales en Texto Plano:
- Archivos sensibles en sysvol sin cifrar (falla de configuración grave).

### Monitoreo Insuficiente de Procesos:
- Ejecución de wscript.exe desde C:\Users\Public no alertada.

### Falta de Segmentación de Red:
- Movimiento lateral a servidor crítico sin controles de red.

### Detectores Sysmon No Implementados:
- Evento ID 15 (creación de ADS) debería generar alertas automáticas.

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