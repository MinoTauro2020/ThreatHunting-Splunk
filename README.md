# ThreatHunting-Splunk 🛡️

## Overview

Welcome to **ThreatHunting-Splunk**, a public repository dedicated to providing Splunk-based threat hunting resources and guides. This project, maintained by **MinoTauro2020**, focuses on creating detailed Markdown files with Splunk Search Processing Language (SPL) queries to help security analysts detect and investigate various cyber threats, such as brute force attacks, Kerberoasting, credential dumping, persistence, and more.

Whether you're hunting for malicious activity in Active Directory, analyzing PowerShell usage, or investigating lateral movement, this repository offers structured guides to enhance your threat hunting capabilities using Splunk.

## Repository Owner

- **Owner**: MinoTauro2020  
- **Profile**: [MinoTauro2020](https://github.com/MinoTauro2020)

## Files in this Repository

Below is a list of all Markdown files in the repository, including their last update details as of **May 20, 2025, 10:02 AM CEST**.

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
| [basic.md](basic.md)                              | Created basic.md                        | Last month            |
| [Initial-Access-Email.md](Initial-Access-Email.md)| Updated Initial-Access-Email.md         | Last month            |
| [README.md](README.md)                            | Initial commit                          | 2 months ago          |

## Getting Started

To use these threat hunting guides:

1. Clone the repository to your local machine:
2. Navigate to the desired Markdown file for the specific threat hunting topic you want to explore.
3. Use the SPL queries provided in each file within your Splunk environment to start hunting for threats.

## Topics Covered

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

