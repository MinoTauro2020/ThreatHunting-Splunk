# eCTHPv2 Threat Hunting Exam - Complete Itinerary and Guide

## Table of Contents
1. [Exam Overview](#exam-overview)
2. [Pre-Exam Configuration](#pre-exam-configuration)
3. [Hunt 1: MAMABEAR Analysis (40 Points)](#hunt-1-mamabear-analysis-40-points)
4. [Hunt 2: .NET Malware Memory Analysis (30 Points)](#hunt-2-net-malware-memory-analysis-30-points)
5. [Hunt 3: Specific TTPs with ELK (30 Points)](#hunt-3-specific-ttps-with-elk-30-points)
6. [Documentation and Deliverables](#documentation-and-deliverables)
7. [Success Criteria](#success-criteria)

## Exam Overview

**Total Points Required**: 75/100 points minimum to pass
**Duration**: Comprehensive threat hunting across 3 scenarios
**Tools**: Splunk, Volatility, ELK Stack

### Point Distribution:
- **Hunt 1** (MAMABEAR): 40 points
- **Hunt 2** (.NET Malware): 30 points  
- **Hunt 3** (Specific TTPs): 30 points

## Pre-Exam Configuration

### 1. VPN Connection Setup
Ensure OpenVPN client is configured and connected before starting.

### 2. Environment Testing
Test connectivity to all exam environments:

```bash
# Test all three scenarios
ping 172.16.85.103  # SCENARIO 1 - Splunk
ping 172.16.85.104  # SCENARIO 2 - Volatility
ping 172.16.85.102  # SCENARIO 3 - ELK
```

### 3. Documentation Preparation
- Create main documentation folder
- Prepare screenshot capture tools
- Set up mind mapping tools for tracking findings

## Hunt 1: MAMABEAR Analysis (40 Points)

### Objective
Hunt for MamaBear threat group activity in ELS Bank using Splunk SIEM, covering the complete cyber kill chain.

### Environment Access
- **URL**: http://172.16.85.103:8000
- **Credentials**: admin / eLSHunter
- **Focus**: Complete attack lifecycle analysis

### Key Investigation Areas

#### 1. Initial Access Detection
**Search Strategy**: Look for unusual file creation and access patterns
```spl
index=* earliest=-7d@d latest=now
| search (EventCode=15 OR EventCode=11)
| eval suspicious_path=if(match(TargetFilename,".*\\Public\\.*|.*ADS.*"), "Yes", "No")
| where suspicious_path="Yes"
| table _time, ComputerName, Image, TargetFilename, ProcessId
| sort -_time
```

#### 2. Persistence Mechanisms
**Search Strategy**: VBS script execution and scheduled tasks
```spl
index=* earliest=-7d@d latest=now
| search (Image="*wscript.exe*" OR Image="*cscript.exe*")
| eval script_location=if(match(CommandLine,".*\\Public\\.*"), "Suspicious", "Normal")
| where script_location="Suspicious"
| table _time, ComputerName, Image, CommandLine, ParentImage
| sort -_time
```

#### 3. Command and Control
**Search Strategy**: Outbound connections to suspicious IPs
```spl
index=* earliest=-7d@d latest=now
| search (EventCode=3 OR sourcetype=firewall)
| eval internal_to_external=if(cidrmatch("192.168.0.0/16", src_ip) AND NOT cidrmatch("192.168.0.0/16", dest_ip), "Yes", "No")
| where internal_to_external="Yes"
| stats count by src_ip, dest_ip, dest_port
| sort -count
```

#### 4. Enumeration Activities
**Search Strategy**: Reconnaissance commands and tools
```spl
index=* earliest=-7d@d latest=now
| search (Image="*whoami.exe*" OR Image="*ipconfig.exe*" OR Image="*net.exe*" OR CommandLine="*SharpHound*")
| table _time, ComputerName, Image, CommandLine, User
| sort -_time
```

#### 5. Privilege Escalation
**Search Strategy**: Credential hunting and findstr usage
```spl
index=* earliest=-7d@d latest=now
| search (Image="*findstr.exe*" AND CommandLine="*password*|*credential*|*login*")
| eval sysvol_access=if(match(CommandLine,".*sysvol.*"), "Critical", "Normal")
| table _time, ComputerName, Image, CommandLine, User, sysvol_access
| sort -_time
```

#### 6. Lateral Movement
**Search Strategy**: Cross-system file transfers and remote execution
```spl
index=* earliest=-7d@d latest=now
| search (EventCode=5145 OR EventCode=5140 OR Image="*psexec*")
| eval lateral_movement=if(match(RelativeTargetName,".*\.exe$|.*\.dll$"), "Executable Transfer", "File Access")
| table _time, ComputerName, src_user, RelativeTargetName, lateral_movement
| sort -_time
```

### Expected Findings Checklist
- [ ] Initial compromise vector identified
- [ ] Persistence mechanism documented
- [ ] C2 communications mapped
- [ ] Enumeration activities cataloged
- [ ] Privilege escalation path traced
- [ ] Lateral movement documented
- [ ] Complete timeline established
- [ ] All affected systems identified

## Hunt 2: .NET Malware Memory Analysis (30 Points)

### Objective
Analyze memory dump for .NET-based malware using Volatility framework.

### Environment Access
- **Connection**: RDP to 172.16.85.104:65520
- **Credentials**: AdminELS / Nu3pmkfyX
- **File**: memdump.mem (Desktop)
- **Profile**: Win10x64_18362

### Analysis Workflow

#### 1. Initial Memory Analysis
```bash
# Navigate to Volatility
cd Downloads/volatility

# Basic system information
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 imageinfo
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 pslist
```

#### 2. .NET Process Detection
```bash
# Look for .NET runtime processes
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 pslist | grep -i "dotnet\|mscor\|clr"

# Check for .NET assemblies in memory
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 dllist -p [PID]
```

#### 3. .NET Malware Hunting Techniques
```bash
# Extract .NET assemblies from memory
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 procdump -p [PID] --dump-dir ./output

# Look for obfuscated .NET code
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 yarascan -Y "{ 4D 5A [2] 00 00 }" --pid=[PID]

# Check for process hollowing indicators
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 hollowfind
```

#### 4. Network Artifacts
```bash
# Network connections
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 netscan

# DNS queries
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 dnshistory
```

#### 5. Advanced .NET Analysis
```bash
# Memory segments analysis
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 memmap -p [PID]

# Registry analysis for .NET persistence
python vol.py -f ~/Desktop/memdump.mem --profile=Win10x64_18362 printkey -K "SOFTWARE\Microsoft\.NETFramework"
```

### .NET Malware Indicators Checklist
- [ ] .NET runtime processes identified
- [ ] Suspicious assemblies extracted
- [ ] Obfuscation techniques detected
- [ ] C2 communications identified
- [ ] Persistence mechanisms found
- [ ] Process injection evidence
- [ ] Timeline of malware execution
- [ ] IOCs documented

## Hunt 3: Specific TTPs with ELK (30 Points)

### Objective
Hunt for specific MITRE ATT&CK techniques using ELK-based SIEM.

### Environment Setup
```bash
# Connect via SSH
ssh hunter@172.16.85.102
# Password: hunter

# Setup environment
cd /opt/elk-detection-lab
sudo ./elk-detection-lab.sh run

# Access Kibana at: http://172.16.85.102:5601
```

### Technique Hunting Queries

#### 1. Timestomping MACE Attributes (T1099)
**Timeline**: 01/04/2019 - 15/05/2019
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "2019-04-01", "lte": "2019-05-15"}}},
        {"terms": {"event.code": ["2", "11"]}},
        {"wildcard": {"process.name": "*touch*"}}
      ]
    }
  }
}
```

#### 2. Meterpreter Migrate to Explorer.exe (T1055)
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"process.parent.name": "explorer.exe"}},
        {"match": {"process.name": "svchost.exe"}},
        {"exists": {"field": "process.pe.original_file_name"}}
      ]
    }
  }
}
```

#### 3. Process Creation through WMI (T1021)
**Timeline**: 01/04/2019 - 01/05/2019
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "2019-04-01", "lte": "2019-05-01"}}},
        {"match": {"process.parent.name": "wmiprvse.exe"}},
        {"match": {"event.code": "1"}}
      ]
    }
  }
}
```

#### 4. MSSQL xp_cmdshell Execution
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"process.parent.name": "sqlservr.exe"}},
        {"wildcard": {"process.command_line": "*xp_cmdshell*"}}
      ]
    }
  }
}
```

#### 5. Chrome Credential Harvesting (T1081)
```json
{
  "query": {
    "bool": {
      "must": [
        {"wildcard": {"file.path": "*Chrome*Login Data*"}},
        {"terms": {"event.code": ["11", "15"]}},
        {"exists": {"field": "process.name"}}
      ]
    }
  }
}
```

#### 6. RottenPotato Privilege Escalation (T1134)
**Date**: 26.05.2019
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "2019-05-26", "lte": "2019-05-27"}}},
        {"wildcard": {"process.name": "*potato*"}},
        {"match": {"event.code": "1"}}
      ]
    }
  }
}
```

### TTP Hunting Checklist
- [ ] T1099 - Timestomping evidence found
- [ ] T1055 - Meterpreter migration detected
- [ ] T1021 - WMI process creation identified
- [ ] MSSQL xp_cmdshell execution traced
- [ ] T1081 - Chrome credential theft detected
- [ ] T1134 - RottenPotato escalation found
- [ ] Timeline correlation completed
- [ ] All IOCs documented

## Documentation and Deliverables

### Required Report Format
Create a comprehensive PDF report with the following structure:

| Hunt | Task | Findings |
|------|------|----------|
| Hunt 1 | MamaBear analysis using Splunk | [Detailed findings with queries and screenshots] |
| Hunt 2 | .NET malware memory analysis | [Volatility commands and extracted artifacts] |
| Hunt 3 | Specific TTPs with ELK | [Kibana queries and detection results] |

### Documentation Best Practices
1. **Screenshot Everything**: Capture all queries, results, and evidence
2. **Include Timestamps**: Document when each activity occurred
3. **Provide Context**: Explain the significance of each finding
4. **Technical Details**: Include exact queries, commands, and parameters used
5. **IOCs**: List all indicators of compromise discovered

### Appendix Requirements
- Complete Splunk queries used
- Full Volatility command outputs
- ELK/Kibana query JSON exports
- Timeline of all discovered activities
- Recommended remediation actions

## Success Criteria

### Minimum Requirements (75+ Points)
- **Hunt 1**: Demonstrate complete attack lifecycle (25+ points minimum)
- **Hunt 2**: Identify .NET malware and its capabilities (20+ points minimum)
- **Hunt 3**: Successfully detect at least 5/6 TTPs (25+ points minimum)

### Excellence Indicators (90+ Points)
- Detailed technical analysis with advanced correlation
- Comprehensive timeline across all three hunts
- Clear remediation recommendations
- Professional documentation quality
- Advanced hunting techniques demonstrated

### Final Checklist
- [ ] All three environments tested and accessible
- [ ] Complete documentation prepared
- [ ] Minimum 75 points worth of findings documented
- [ ] PDF report formatted according to requirements
- [ ] All technical details included in appendices
- [ ] Ready for submission

---

**Remember**: Document everything as you go. Mind mapping and continuous note-taking are essential for success in this comprehensive threat hunting examination.