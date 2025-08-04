# ThreatHunting-Splunk 🛡️

## Overview

Welcome to **ThreatHunting-Splunk**, a public repository dedicated to providing Splunk-based threat hunting resources and guides. This project, maintained by **MinoTauro2020**, focuses on creating detailed Markdown files with Splunk Search Processing Language (SPL) queries to help security analysts detect and investigate various cyber threats, such as brute force attacks, Kerberoasting, credential dumping, persistence, and more.

**🆕 Latest Updates**: Added 6 new advanced threat hunting investigations focusing on sophisticated attack techniques like Golden Ticket detection, LOLBins abuse, Shadow Credentials, NTLM Relay, Process Hollowing, and Registry Persistence. These investigations feature:
- **Precise, non-generic SPL queries** tailored for specific attack patterns
- **Advanced correlation techniques** across multiple data sources
- **Detailed detection rationale** with clear indicators of compromise
- **Comprehensive coverage** from basic detection to advanced hunting
- **Real-world applicability** based on current threat landscape

Whether you're hunting for malicious activity in Active Directory, analyzing PowerShell usage, or investigating lateral movement, this repository offers structured guides to enhance your threat hunting capabilities using Splunk.

## Repository Owner

- **Owner**: MinoTauro2020  
- **Profile**: [MinoTauro2020](https://github.com/MinoTauro2020)

## 🎯 **eCTHPv2 Threat Hunting Exam Resources (New!)**

Complete exam preparation materials for the eCTHPv2 (eLearnSecurity Certified Threat Hunting Professional v2) certification:

| **File Name** | **Description** | **Points** |
|---------------|-----------------|------------|
| [eCTHPv2-Exam-Itinerary.md](eCTHPv2-Exam-Itinerary.md) | Complete exam itinerary covering all 3 hunts with detailed methodology | Master Guide |
| [Analisis-MAMABEAR.md](Analisis-MAMABEAR.md) | Enhanced MAMABEAR analysis with Splunk queries for Hunt 1 | 40 Points |
| [DotNet-Malware-Memory-Analysis.md](DotNet-Malware-Memory-Analysis.md) | Comprehensive Volatility guide for .NET malware hunting (Hunt 2) | 30 Points |
| [ELK-TTP-Hunting-Guide.md](ELK-TTP-Hunting-Guide.md) | ELK-based hunting for specific TTPs with MITRE ATT&CK techniques (Hunt 3) | 30 Points |

**Total Coverage**: 100+ points with detailed technical guidance for exam success.

## Files in this Repository

Below is a list of all Markdown files in the repository, including their last update details.

### 🆕 **Advanced Threat Hunting Investigations (Latest)**

| **File Name**                                      | **Description**                          | **Status**            |
|----------------------------------------------------|------------------------------------------|-----------------------|
| [Golden-Ticket-Detection.md](Golden-Ticket-Detection.md) | Advanced detection of Golden Ticket attacks and Kerberos TGT forgery | ✅ New                |
| [LOLBins-Detection.md](LOLBins-Detection.md)      | Living Off The Land Binaries abuse detection | ✅ New                |
| [Shadow-Credentials-Attack.md](Shadow-Credentials-Attack.md) | ADCS Certificate abuse and Shadow Credentials detection | ✅ New                |
| [NTLM-Relay-Attacks.md](NTLM-Relay-Attacks.md)   | Comprehensive NTLM relay attack detection | ✅ New                |
| [Process-Hollowing-Detection.md](Process-Hollowing-Detection.md) | Process injection and hollowing technique detection | ✅ New                |
| [Registry-Persistence-Detection.md](Registry-Persistence-Detection.md) | Registry-based persistence mechanism detection | ✅ New                |

### 📚 **Existing Threat Hunting Investigations**

| **File Name**                                      | **Last Update Description**              | **Time Since Update** |
|----------------------------------------------------|------------------------------------------|-----------------------|
| [Internal-Recon.md](Internal-Recon.md)            | Created Internal-Recon.md               | Now                   |
| [Macros.md](Macros.md)                            | Created Macros.md                       | 1 minute ago          |
| [Scripts.md](Scripts.md)                          | Updated Scripts.md                      | 1 minute ago          |
| [Movimiento-Lateral.md](Movimiento-Lateral.md)    | Updated Movimiento-Lateral.md           | 2 minutes ago         |
| [Powershell.md](Powershell.md)                    | Created Powershell.md                   | 3 minutes ago         |
| [Persistencie.md](Persistencie.md)                | Updated Persistencie.md                 | 4 minutes ago         |
| [CredentialDumping.md](CredentialDumping.md)      | Created CredentialDumping.md            | 10 minutes ago        |
| [AD-Kerberoasting.md](AD-Kerberoasting.md)        | Created AD-Kerberoasting.md             | 11 minutes ago        |
| [BruteForce-AD.md](BruteForce-AD.md)              | Created BruteForce-AD.md                | 11 minutes ago        |
| [Command-Control.md](Command-Control.md)          | Updated Command-Control.md              | 16 minutes ago        |
| [Exfiltration.md](Exfiltration.md)                | Updated Exfiltration.md                 | 17 minutes ago        |
| [Initial-Access-BruteForce.md](Initial-Access-BruteForce.md) | Updated Initial-Access-BruteForce.md | Yesterday             |
| [Initial-Access-w3wp-IIS.md](Initial-Access-w3wp-IIS.md) | Renamed from Initial-Access-w3wpIIS.md | Yesterday             |
| [Basics.md](Basics.md)                            | Renamed from table.md to Basics.md      | Last month            |
| [Initial-Access-Email.md](Initial-Access-Email.md)| Updated Initial-Access-Email.md         | Last month            |
| [README.md](README.md)                            | Initial commit                          | 2 months ago          |

## Getting Started

To use these threat hunting guides:

1. Clone the repository to your local machine:
2. Navigate to the desired Markdown file for the specific threat hunting topic you want to explore.
3. Use the SPL queries provided in each file within your Splunk environment to start hunting for threats.

## Topics Covered

### 🔥 **Advanced Threat Hunting (New)**
- **eCTHPv2 Exam Suite**: Complete certification exam preparation with 100+ point coverage
- **Golden Ticket Detection**: Advanced detection of Kerberos TGT forgery and timeline analysis.
- **Living Off The Land Binaries (LOLBins)**: Detect abuse of legitimate Windows binaries for malicious purposes.
- **Shadow Credentials Attack**: Hunt for ADCS certificate abuse and msDS-KeyCredentialLink manipulation.
- **NTLM Relay Attacks**: Comprehensive detection of credential relay and cross-protocol attacks.
- **Process Hollowing Detection**: Identify process injection, hollowing, and memory manipulation techniques.
- **Registry Persistence Mechanisms**: Detect sophisticated registry-based persistence across multiple attack vectors.
- **.NET Malware Memory Analysis**: Volatility-based hunting for .NET malware in memory dumps.
- **ELK-based TTP Hunting**: Specific MITRE ATT&CK technique detection using Elasticsearch and Kibana.

### 📚 **Core Threat Hunting**
- **Brute Force Attacks**: Detect brute force and password spraying in Active Directory.
- **Kerberoasting**: Identify Kerberoasting attempts using Splunk queries.
- **Credential Dumping**: Hunt for credential dumping activities like LSASS memory dumps.
- **Persistence**: Investigate persistence mechanisms (WMI, registry, filesystem).
- **PowerShell Abuse**: Detect renamed, unmanaged, and encoded PowerShell usage.
- **Lateral Movement**: Identify lateral movement through admin shares and WMI.
- **Malicious Documents**: Hunt for malicious Word documents and macros.
- **Internal Reconnaissance**: Detect internal recon activity using common commands.
- **Exfiltration**: Investigate data exfiltration attempts.
- **Command and Control**: Look for C2 communication patterns.

## Contributing

Contributions are welcome! If you have additional SPL queries, hunting techniques, or improvements, feel free to:

1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a pull request with a clear description of your updates.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (if applicable).

## Contact

For any questions or issues, reach out to **MinoTauro2020** via GitHub or open an issue in the repository.

Happy hunting! 🔍

