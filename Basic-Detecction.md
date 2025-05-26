# Splunk Queries – Hunting & Incident Response en entornos Windows/AD

---

## Índice

1. [Autenticaciones sospechosas y movimiento lateral](#autenticaciones-sospechosas-y-movimiento-lateral)
2. [Enumeración y abuso de SMB/NetBIOS](#enumeracion-y-abuso-de-smbnetbios)
3. [Detección de ataques Kerberos](#deteccion-de-ataques-kerberos)
4. [Detección de ataques NTLM/relay](#deteccion-de-ataques-ntlmrelay)
5. [Hunting con Sysmon (procesos, conexiones, acceso a LSASS, etc.)](#hunting-con-sysmon)
6. [Windows Firewall y tráfico sospechoso](#windows-firewall-y-trafico-sospechoso)
7. [Otras queries útiles](#otras-queries-utiles)
8. [Referencias y recursos](#referencias-y-recursos)

---

## 1. Autenticaciones sospechosas y movimiento lateral

### Logons tipo 3 desde IPs externas
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3
| stats count by Account_Name, IpAddress, ComputerName
| where NOT like(IpAddress, "10.%") AND NOT like(IpAddress, "192.168.%")
```

### Intentos de Pass-the-Hash
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| where Logon_Type=3 AND Authentication_Package="NTLM"
| stats count by Account_Name, IpAddress
```

---

## 2. Enumeración y abuso de SMB/NetBIOS

### Acceso a IPC$ share
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5140
| search Share_Name="\\IPC$"
| stats count by Account_Name, IpAddress, ComputerName
```

### Uso de puertos altos origen a SMB (hunting scanning)
```splunk
index=firewall sourcetype=windows_firewall dest_port=445
| stats count by src_ip, dest_ip
```

---

## 3. Detección de ataques Kerberos

### AS-REP Roasting
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| table _time, ComputerName, Account_Name, Client_Address
```

### Kerberoasting (TGS requests a cuentas de servicio)
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search Service_Name="krbtgt"
| stats count by Account_Name, Client_Address
```

---

## 4. Detección de ataques NTLM/relay

### Eventos NTLM fallidos (relays, brute force)
```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4776)
| where Authentication_Package="NTLM"
| table _time, Account_Name, IpAddress, Failure_Reason
```

---

## 5. Hunting con Sysmon

### Procesos sospechosos lanzando conexiones SMB
```splunk
index=sysmon EventID=3 DestinationPort=445
| stats count by SourceIp, DestinationIp, Image
```

### Acceso a LSASS (intentos de dump de credenciales)
```splunk
index=sysmon EventID=10 TargetImage="C:\\Windows\\System32\\lsass.exe"
| table _time, SourceImage, User, Computer
```

---

## 6. Windows Firewall y tráfico sospechoso

### Extracción de puertos y conexiones
```splunk
index=firewall sourcetype=windows_firewall
| rex field=_raw "^\S+\s+\S+\s+\S+\s+(?P<protocol>\S+)\s+(?P<src_ip>\S+)\s+(?P<dest_ip>\S+)\s+(?P<src_port>\d+)\s+(?P<dest_port>\d+)"
| stats count by src_ip, dest_ip, dest_port
```

---

## 7. Otras queries útiles

### Cuentas bloqueadas (posible brute force)
```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4740
| stats count by Account_Name, ComputerName, IpAddress
```

### Modificación de cuentas (creación, cambios de grupo, etc.)
```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4728 OR EventCode=4729)
| table _time, Account_Name, Subject_Account_Name, ComputerName
```

---

## 8. Referencias y recursos

- [Splunk Security Content](https://research.splunk.com/)
- [Sigma rules](https://sigmahq.io/)
- [Windows Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [HackTricks - Splunk](https://book.hacktricks.xyz/logging-siem/splunk/splunk-cheat-sheet)
