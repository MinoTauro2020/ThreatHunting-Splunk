# ELK-Based TTP Hunting Guide - eCTHPv2 Hunt 3

## Overview

This guide provides comprehensive hunting queries and methodologies for detecting specific MITRE ATT&CK techniques using the ELK Stack (Elasticsearch, Logstash, Kibana). The focus is on the six specific TTPs required for eCTHPv2 Hunt 3.

## Environment Setup

### Initial Configuration
```bash
# SSH Connection
ssh hunter@172.16.85.102
# Password: hunter

# Setup ELK environment
cd /opt/elk-detection-lab
sudo ./elk-detection-lab.sh run

# Access Kibana: http://172.16.85.102:5601
```

### Required Indexes
- `winlogbeat-*` - Windows Event Logs
- `sysmon-*` - Sysmon Events
- `filebeat-*` - File System Events
- `packetbeat-*` - Network Traffic

## TTP 1: Timestomping MACE Attributes (T1099)
**Timeline: 01/04/2019 - 15/05/2019**

### Description
Attackers modify file timestamps to evade detection and blend in with legitimate files.

### Detection Strategy
Monitor for:
- File creation/modification events with unusual timestamp patterns
- Use of tools like `touch`, `timestomp`, or PowerShell timestamp modification
- Files with timestamps that don't match creation patterns

### Kibana Queries

#### Basic Timestomping Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-15T23:59:59Z"
            }
          }
        },
        {
          "terms": {
            "event.code": ["2", "11", "15"]
          }
        }
      ],
      "should": [
        {
          "wildcard": {
            "process.name": "*touch*"
          }
        },
        {
          "wildcard": {
            "process.command_line": "*timestamp*"
          }
        },
        {
          "wildcard": {
            "process.command_line": "*SetFileTime*"
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

#### PowerShell Timestomping Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-15T23:59:59Z"
            }
          }
        },
        {
          "match": {
            "process.name": "powershell.exe"
          }
        },
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.command_line": "*CreationTime*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*LastWriteTime*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*LastAccessTime*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*SetFileTime*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

#### Advanced Detection - Suspicious Timestamp Patterns
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-15T23:59:59Z"
            }
          }
        },
        {
          "script": {
            "script": {
              "source": "Math.abs(doc['file.created'].value.millis - doc['@timestamp'].value.millis) > 86400000",
              "lang": "painless"
            }
          }
        }
      ]
    }
  }
}
```

## TTP 2: Meterpreter Migrate to Explorer.exe (T1055)

### Description
Process injection technique where Meterpreter migrates from an untrusted process to a trusted process (explorer.exe).

### Detection Strategy
Monitor for:
- Suspicious child processes of explorer.exe
- Unusual memory patterns in explorer.exe
- Network connections from explorer.exe to external IPs

### Kibana Queries

#### Basic Process Injection Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "process.parent.name": "explorer.exe"
          }
        },
        {
          "terms": {
            "event.code": ["1", "8", "10"]
          }
        }
      ],
      "should": [
        {
          "wildcard": {
            "process.name": "*svchost*"
          }
        },
        {
          "wildcard": {
            "process.name": "*rundll32*"
          }
        },
        {
          "wildcard": {
            "process.name": "*regsvr32*"
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

#### Meterpreter Migration Indicators
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "event.code": "10"
          }
        },
        {
          "match": {
            "process.target.name": "explorer.exe"
          }
        },
        {
          "terms": {
            "process.access": ["0x1F3FFF", "0x1FFFFF"]
          }
        }
      ]
    }
  }
}
```

#### Network Connections from Explorer.exe
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "process.name": "explorer.exe"
          }
        },
        {
          "match": {
            "event.code": "3"
          }
        },
        {
          "bool": {
            "must_not": [
              {
                "terms": {
                  "destination.port": ["80", "443", "53"]
                }
              }
            ]
          }
        }
      ]
    }
  }
}
```

## TTP 3: Process Creation through WMI (T1021)
**Timeline: 01/04/2019 - 01/05/2019**

### Description
Lateral movement technique using WMI to execute processes on remote systems.

### Detection Strategy
Monitor for:
- wmiprvse.exe spawning unusual child processes
- WMI event consumer creation
- Remote WMI connections

### Kibana Queries

#### Basic WMI Process Creation
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-01T23:59:59Z"
            }
          }
        },
        {
          "match": {
            "process.parent.name": "wmiprvse.exe"
          }
        },
        {
          "match": {
            "event.code": "1"
          }
        }
      ]
    }
  }
}
```

#### Suspicious WMI Commands
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-01T23:59:59Z"
            }
          }
        },
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.command_line": "*Win32_Process*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*Create*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*wmic*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

#### WMI Event Consumer Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-04-01T00:00:00Z",
              "lte": "2019-05-01T23:59:59Z"
            }
          }
        },
        {
          "terms": {
            "event.code": ["19", "20", "21"]
          }
        },
        {
          "wildcard": {
            "winlog.event_data.Consumer": "*CommandLineEventConsumer*"
          }
        }
      ]
    }
  }
}
```

## TTP 4: MSSQL xp_cmdshell Execution

### Description
Abuse of SQL Server's xp_cmdshell stored procedure to execute operating system commands.

### Detection Strategy
Monitor for:
- sqlservr.exe spawning cmd.exe or other processes
- xp_cmdshell usage in SQL logs
- Unusual network connections from SQL Server

### Kibana Queries

#### Basic xp_cmdshell Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "process.parent.name": "sqlservr.exe"
          }
        },
        {
          "terms": {
            "process.name": ["cmd.exe", "powershell.exe", "bcp.exe"]
          }
        },
        {
          "match": {
            "event.code": "1"
          }
        }
      ]
    }
  }
}
```

#### SQL Server Command Line Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "process.command_line": "*xp_cmdshell*"
          }
        }
      ]
    }
  }
}
```

#### SQL Server Suspicious Child Processes
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "process.parent.name": "sqlservr.exe"
          }
        },
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.command_line": "*whoami*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*net user*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*systeminfo*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*ping*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

## TTP 5: Chrome Credential Harvesting (T1081)

### Description
Theft of saved credentials from Google Chrome browser databases.

### Detection Strategy
Monitor for:
- Access to Chrome's Login Data files
- Processes reading Chrome profile directories
- Database file operations on Chrome stores

### Kibana Queries

#### Chrome Login Data Access
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "file.path": "*Chrome*Login Data*"
          }
        },
        {
          "terms": {
            "event.code": ["11", "15"]
          }
        }
      ]
    }
  }
}
```

#### Chrome Profile Directory Access
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "wildcard": {
            "file.path": "*Google\\Chrome\\User Data*"
          }
        },
        {
          "bool": {
            "must_not": [
              {
                "match": {
                  "process.name": "chrome.exe"
                }
              }
            ]
          }
        }
      ]
    }
  }
}
```

#### Credential Theft Tools
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.command_line": "*Login Data*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*sqlite3*"
                }
              },
              {
                "wildcard": {
                  "process.name": "*lazagne*"
                }
              },
              {
                "wildcard": {
                  "process.name": "*browserpassview*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

#### PowerShell Chrome Credential Access
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "process.name": "powershell.exe"
          }
        },
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.command_line": "*Chrome*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*Login Data*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*sqlite*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

## TTP 6: RottenPotato Privilege Escalation (T1134)
**Date: 26.05.2019**

### Description
Local privilege escalation technique that exploits the Windows DCOM service to escalate from service account to SYSTEM.

### Detection Strategy
Monitor for:
- Processes named with "potato" variants
- COM object manipulations
- Token impersonation events

### Kibana Queries

#### RottenPotato Process Detection
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-05-26T00:00:00Z",
              "lte": "2019-05-27T23:59:59Z"
            }
          }
        },
        {
          "bool": {
            "should": [
              {
                "wildcard": {
                  "process.name": "*potato*"
                }
              },
              {
                "wildcard": {
                  "process.command_line": "*potato*"
                }
              },
              {
                "wildcard": {
                  "file.name": "*potato*"
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

#### Token Manipulation Events
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-05-26T00:00:00Z",
              "lte": "2019-05-27T23:59:59Z"
            }
          }
        },
        {
          "terms": {
            "event.code": ["4624", "4648", "4672"]
          }
        },
        {
          "match": {
            "winlog.event_data.LogonType": "3"
          }
        }
      ]
    }
  }
}
```

#### DCOM Service Abuse
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "2019-05-26T00:00:00Z",
              "lte": "2019-05-27T23:59:59Z"
            }
          }
        },
        {
          "match": {
            "process.name": "dllhost.exe"
          }
        },
        {
          "wildcard": {
            "process.command_line": "*{EEAA76A8-11AC-4C3D-8E2C-F019A4CCC*"
          }
        }
      ]
    }
  }
}
```

## Correlation and Timeline Analysis

### Cross-TTP Correlation Query
```json
{
  "query": {
    "bool": {
      "should": [
        {
          "bool": {
            "must": [
              {"match": {"process.name": "explorer.exe"}},
              {"match": {"event.code": "3"}}
            ]
          }
        },
        {
          "bool": {
            "must": [
              {"match": {"process.parent.name": "wmiprvse.exe"}},
              {"match": {"event.code": "1"}}
            ]
          }
        },
        {
          "bool": {
            "must": [
              {"match": {"process.parent.name": "sqlservr.exe"}},
              {"terms": {"process.name": ["cmd.exe", "powershell.exe"]}}
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}
```

### Timeline Aggregation
```json
{
  "aggs": {
    "timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      },
      "aggs": {
        "techniques": {
          "terms": {
            "script": {
              "source": """
                if (doc['process.name'].size() > 0) {
                  def process = doc['process.name'].value;
                  if (process == 'explorer.exe' && doc['event.code'].value == '3') return 'T1055-Process_Injection';
                  if (doc['process.parent.name'].size() > 0 && doc['process.parent.name'].value == 'wmiprvse.exe') return 'T1021-WMI_Execution';
                  if (doc['process.parent.name'].size() > 0 && doc['process.parent.name'].value == 'sqlservr.exe') return 'MSSQL_xp_cmdshell';
                  if (process.contains('potato')) return 'T1134-RottenPotato';
                }
                return 'Other';
              """
            }
          }
        }
      }
    }
  }
}
```

## Visualization and Dashboards

### Key Metrics Dashboard
1. **TTP Detection Count** - Number of each technique detected
2. **Timeline View** - Chronological visualization of all TTPs
3. **Process Tree** - Parent-child process relationships
4. **Network Connections** - Outbound connections from compromised processes
5. **File Operations** - Suspicious file access patterns

### Alert Configuration
```json
{
  "trigger": {
    "schedule": {
      "interval": "5m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "query": {
            "bool": {
              "should": [
                {"match": {"process.parent.name": "wmiprvse.exe"}},
                {"wildcard": {"process.name": "*potato*"}},
                {"match": {"process.parent.name": "sqlservr.exe"}},
                {"wildcard": {"file.path": "*Login Data*"}}
              ],
              "minimum_should_match": 1
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gt": 0
      }
    }
  }
}
```

## Reporting Template

### Executive Summary
- Total TTPs detected: X/6
- High-risk findings: [List critical detections]
- Timeline: [Attack progression overview]

### Technical Findings

| TTP | Status | Evidence | Risk Level |
|-----|--------|----------|------------|
| T1099 - Timestomping | [Detected/Not Detected] | [Query results, timestamps] | [High/Medium/Low] |
| T1055 - Process Injection | [Detected/Not Detected] | [Process details, PIDs] | [High/Medium/Low] |
| T1021 - WMI Execution | [Detected/Not Detected] | [WMI commands, targets] | [High/Medium/Low] |
| MSSQL xp_cmdshell | [Detected/Not Detected] | [SQL commands executed] | [High/Medium/Low] |
| T1081 - Credential Harvesting | [Detected/Not Detected] | [Files accessed, tools used] | [High/Medium/Low] |
| T1134 - RottenPotato | [Detected/Not Detected] | [Privilege escalation evidence] | [High/Medium/Low] |

### Recommendations
1. **Immediate Actions**: [Containment and response steps]
2. **Detection Improvements**: [Enhanced monitoring rules]
3. **Prevention Measures**: [Security controls to implement]

## Best Practices

1. **Query Optimization**: Use specific time ranges to improve performance
2. **False Positive Reduction**: Add exclusions for known-good processes
3. **Correlation**: Combine multiple indicators for higher confidence
4. **Documentation**: Save all queries and results for evidence
5. **Validation**: Manually verify critical findings
6. **Timeline**: Maintain chronological order of events

This comprehensive guide provides the necessary queries and methodology to successfully detect all six specified TTPs in the eCTHPv2 Hunt 3 scenario using ELK Stack.