# 🛡️ Hunting y Detección de Shadow Credentials Attack (ADCS Certificate Abuse)

---

## 🔥 Lo primero que hay que buscar (detección base)

### **1. Modificaciones del atributo msDS-KeyCredentialLink (Shadow Credentials)**
Busca cambios en el atributo que almacena las credenciales de clave pública para autenticación:
- **Log:** Security Event 5136 (Directory Service Changes)
- **Indicador clave:** Modificaciones del atributo msDS-KeyCredentialLink en cuentas de usuario

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5136
| search AttributeLDAPDisplayName="msDS-KeyCredentialLink"
| table _time, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue, OperationType
| sort -_time
```
- **Revisa:** ¿Qué cuentas están siendo modificadas? ¿Quién realiza los cambios? ¿Hay patrones de modificación masiva?

---

## 🔎 Afinando la búsqueda y correlación (detección avanzada)

> Usa estas queries para reducir falsos positivos y priorizar los hallazgos.

### **2. Shadow Credentials en cuentas privilegiadas**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5136
| search AttributeLDAPDisplayName="msDS-KeyCredentialLink" AND OperationType="%%14674"
| search (ObjectDN="*admin*" OR ObjectDN="*svc*" OR ObjectDN="*service*" OR ObjectDN="CN=Domain Admins*" OR ObjectDN="CN=Enterprise Admins*")
| table _time, SubjectUserName, ObjectDN, AttributeValue
| sort -_time
```
- Detecta adición de Shadow Credentials a cuentas de alto privilegio.

---

### **3. Usuarios no privilegiados modificando atributos de otros usuarios**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5136
| search AttributeLDAPDisplayName="msDS-KeyCredentialLink"
| eval target_user = replace(ObjectDN, "^CN=([^,]+),.*", "\1")
| eval modifier_user = SubjectUserName
| where lower(target_user) != lower(modifier_user)
| search NOT (SubjectUserName="*admin*" OR SubjectUserName="*svc*")
| table _time, SubjectUserName, target_user, ObjectDN, OperationType
| sort -_time
```
- Identifica usuarios estándar modificando credenciales de otros usuarios.

---

### **4. Autenticación PKI subsecuente tras modificación de Shadow Credentials**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5136
| search AttributeLDAPDisplayName="msDS-KeyCredentialLink" AND OperationType="%%14674"
| eval target_user = replace(ObjectDN, "^CN=([^,]+),.*", "\1")
| rename _time as mod_time
| join target_user [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 OR EventCode=4769
    | search CertificateIssuerName!=""
    | rename TargetUserName as target_user, _time as auth_time
    | table target_user, auth_time, CertificateIssuerName, IpAddress
]
| where auth_time > mod_time AND auth_time < (mod_time + 3600)
| table mod_time, target_user, SubjectUserName, auth_time, CertificateIssuerName, IpAddress
| sort -mod_time
```
- Correlaciona modificaciones de Shadow Credentials con autenticación PKI posterior.

---

### **5. Enumeración masiva de atributos msDS-KeyCredentialLink**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4662
| search ObjectType="*bf967aba-0de6-11d0-a285-00aa003049e2*" AND Properties="*5b47d60f-6090-40b2-9f37-2a4de88f3063*"
| stats count by SubjectUserName, IpAddress
| where count > 10
| sort -count
```
- Detecta lectura masiva del atributo msDS-KeyCredentialLink (reconnaissance).

---

### **6. Detección de herramientas relacionadas con Shadow Credentials**
```splunk
index=dc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (CommandLine="*Whisker*" OR CommandLine="*pyWhisker*" OR CommandLine="*msDS-KeyCredentialLink*" OR CommandLine="*Add-KeyCredential*" OR CommandLine="*Get-KeyCredential*")
| table _time, Computer, Image, CommandLine, User, ParentImage
| sort -_time
```
- Identifica herramientas conocidas para Shadow Credentials attack.

---

### **7. Cambios en Key Trust para autenticación (WHfB)**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5136
| search AttributeLDAPDisplayName="msDS-KeyCredentialLink" OR AttributeLDAPDisplayName="userCertificate"
| stats count by ObjectDN, AttributeLDAPDisplayName, OperationType
| where count > 1
| sort -count
```
- Detecta cuentas con múltiples cambios en atributos de certificados.

---

### **8. Autenticación Kerberos con certificados desde IPs inusuales**
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768
| search CertificateIssuerName!="" AND CertificateSerialNumber!=""
| iplocation IpAddress
| stats count by TargetUserName, Country, City, CertificateIssuerName
| where count < 3 AND Country!="Unknown"
| sort -count
```
- Identifica autenticación PKI desde ubicaciones geográficas inusuales.

---

## ⚡️ Alertas automáticas y dashboards sugeridos

- **Alerta 1:**  
  Modificación del atributo msDS-KeyCredentialLink en cualquier cuenta privilegiada.
- **Alerta 2:**  
  Usuario no administrativo modificando msDS-KeyCredentialLink de otro usuario.
- **Alerta 3:**  
  Más de 5 lecturas del atributo msDS-KeyCredentialLink por el mismo usuario en 1 hora.
- **Dashboard:**  
  - Panel de modificaciones de Shadow Credentials por usuario y timestamp.
  - Panel de correlación entre modificaciones y autenticación PKI subsecuente.
  - Panel geográfico de autenticaciones con certificados.
- **Integración con otros eventos:**  
  - Correlaciona con eventos 4648 (explicit credential use) para detectar lateral movement.
  - Integra con logs de ADCS para validation de certificados emitidos.
  - Cruza con eventos de PowerShell (EventCode 4103/4104) para detectar scripts maliciosos.

---

# Shadow Credentials: Técnicas de ataque y su detección

1. **Shadow Credentials clásico (Key Trust)**
   - El atacante modifica msDS-KeyCredentialLink para añadir su propia clave pública.
   - **Detección:** Eventos 5136 con cambios en msDS-KeyCredentialLink, especialmente en cuentas privilegiadas.

2. **Certificate Request Abuse**
   - Uso de certificados obtenidos vía Shadow Credentials para autenticación Kerberos.
   - **Detección:** Correlación entre modificaciones del atributo y autenticación PKI posterior.

3. **Persistence via Certificate**
   - Mantenimiento de acceso mediante certificados válidos por largos períodos.
   - **Detección:** Autenticación PKI repetida sin actividad administrativa legítima.

## 🛠️ Buenas prácticas de hunting y respuesta

- **Monitorea todos los cambios en atributos relacionados con PKI en AD.**
- Implementa alertas para modificaciones de msDS-KeyCredentialLink en cuentas críticas.
- Correlaciona modificaciones de atributos con autenticación PKI subsecuente.
- Audita permisos sobre atributos sensibles y restringe WritProperty rights.
- Considera deshabilitar Key Trust Authentication si no es necesario.
- Implementa certificate monitoring y revocation procedures.
- Despliega detección de herramientas como Whisker, pyWhisker en endpoints.

---

## Tabla de Consultas SPL para Hunt for Shadow Credentials

| **Consulta**                                                                 | **Propósito**                                                                 |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink" \| table _time, SubjectUserName, ObjectDN, OperationType` | Detecta todas las modificaciones del atributo msDS-KeyCredentialLink. |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink" ObjectDN="*admin*" \| table _time, SubjectUserName, ObjectDN` | Identifica Shadow Credentials targeting cuentas administrativas. |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4768 CertificateIssuerName!="" \| table _time, TargetUserName, IpAddress, CertificateIssuerName, CertificateSerialNumber` | Detecta autenticación Kerberos usando certificados (post-Shadow Credentials). |
| `index="ad_hunting" source=XmlWinEventLog:Security EventCode=4662 Properties="*5b47d60f-6090-40b2-9f37-2a4de88f3063*" \| stats count by SubjectUserName \| where count > 10` | Identifica enumeración masiva del atributo msDS-KeyCredentialLink. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*Whisker*" \| table _time, Computer, CommandLine, User` | Detecta uso de herramientas Whisker para Shadow Credentials attack. |
| `index="ad_hunting" source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 ScriptBlockText="*msDS-KeyCredentialLink*" \| table _time, Computer, ScriptBlockText` | Identifica scripts PowerShell manipulando Shadow Credentials. |

---

## 🧠 Consejos finales de defensa y hunting

- **Implementa Tier 0 protection para cuentas que no requieren Key Trust Authentication.**
- Despliega monitoring de ADCS para detectar emisión anómala de certificados.
- Automatiza respuesta para revocar certificados asociados con Shadow Credentials detectados.
- Considera implementar Conditional Access policies basadas en certificate properties.
- Simula Shadow Credentials attacks en ejercicios purple team para validar detección.
- Mantén inventario de cuentas con Key Trust habilitado y audita regularmente.