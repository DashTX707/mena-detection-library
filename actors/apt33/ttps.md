# APT33 (G0064) — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence. MITRE ID: G0064.
> Enriched from MITRE ATT&CK G0064 + Mandiant & Microsoft (Peach Sandstorm) reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **48** across **14** tactics. Aviation/energy espionage + password-spray identity attacks + assessed Shamoon destructive set (Impact).

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | APT33 obtains and uses a mix of commodity and open-source tooling — DarkComet, NanoCore, QuasarRAT, NetWire, PoshC2, AutoIt, and later AzureHound/Roadtools/AnyDesk — alongside its custom TURNEDUP and POWERTON backdoors, reducing reliance on wholly custom malware. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | APT33's signature initial-access vector: spear-phishing emails with recruitment/job-vacancy lures carrying malicious attachments (.hta / HTML application content and Office documents) that drop TURNEDUP and commodity RATs, tailored to aviation, aerospace and energy-sector employees. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | The actor also delivers links in spear-phishing emails leading to credential-harvesting pages or malware droppers hosted on domains masquerading as the spoofed aviation/defense organizations (e.g. alsalam[.]ddns[.]net, ngaaksa[.]ga). |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | APT33 uses valid credentials — harvested via phishing or obtained through password spraying — to access on-premises and cloud environments as legitimate users, blending into normal authentication traffic. |
| Valid Accounts: Cloud Accounts | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | As Peach Sandstorm, the actor authenticated to victim Microsoft Entra ID / Azure cloud tenants using credentials obtained through password spraying, then operated as a legitimate cloud user to enumerate and exfiltrate data. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | A signature APT33/Peach Sandstorm technique: large-scale password spraying against cloud and on-prem identity systems, attempting a small set of common passwords against thousands of accounts across many tenants, throttled to Iran-business-hours and routed through TOR to evade lockout and detection thresholds. |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Beyond spraying, the actor conducts broader brute-force credential guessing against externally facing authentication services (email, SSO, remote access) as part of initial access, consistent with Iranian-nexus brute-force activity documented by Microsoft and joint government advisories. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | On compromised hosts the actor dumps credentials from LSASS memory to obtain additional accounts for lateral movement per the G0064 mapping. |
| OS Credential Dumping: LSA Secrets | [T1003.004](https://attack.mitre.org/techniques/T1003/004/) | The actor extracts LSA secrets from the registry/SECURITY hive to recover stored service and account credentials per the G0064 mapping. |
| OS Credential Dumping: Cached Domain Credentials | [T1003.005](https://attack.mitre.org/techniques/T1003/005/) | The actor harvests cached domain credentials (MSCACHE/DCC) from compromised hosts to authenticate as domain users per the G0064 mapping. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | The actor searches for credentials stored in files on compromised systems per the G0064 mapping. |
| Unsecured Credentials: Group Policy Preferences | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | The actor recovers passwords embedded in Group Policy Preferences (GPP) XML files on SYSVOL, decrypting them with the public AES key to obtain local/service account credentials per the G0064 mapping. |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | The actor extracts credentials from local password stores on compromised hosts per the G0064 mapping. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | The actor harvests credentials saved in web browsers on compromised hosts per the G0064 mapping. |
| Network Sniffing | [T1040](https://attack.mitre.org/techniques/T1040/) | The actor uses network sniffing to capture credentials and other traffic on compromised networks per the G0064 mapping. |
| Forge Web Credentials: SAML Tokens | [T1606.002](https://attack.mitre.org/techniques/T1606/002/) | As Peach Sandstorm, the actor conducted Golden SAML attacks against AD FS servers — using a compromised token-signing certificate to forge SAML tokens and authenticate to federated cloud services as arbitrary users, bypassing MFA. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | APT33 exploits client-application vulnerabilities to gain code execution — most notably CVE-2017-11774 (Microsoft Outlook Home Page) to launch its payloads on targeted hosts. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Victims are induced to click links in recruitment-themed emails leading to malware-download URLs or credential-harvesting pages on spoofed-organization domains — a required user action in the actor's link-based campaigns. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Victims are lured into opening malicious attachments — .hta / HTML application files and macro-enabled documents in job-vacancy lures — that execute droppers deploying TURNEDUP and commodity RATs. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell is central to APT33's post-exploitation: the custom POWERTON backdoor is PowerShell-based, the actor uses the PoshC2 PowerShell C2 framework, and Peach Sandstorm cloud operations leverage PowerShell-driven Entra ID / Azure enumeration tooling. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | APT33 uses Visual Basic scripting (VBScript in .hta/HTML application droppers and VBA macros) as part of its delivery and execution chain per the G0064 mapping. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Event Triggered Execution: Windows Management Instrumentation Event Subscription | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | The actor establishes persistence via WMI event subscriptions that trigger execution of its implants on defined system events per the G0064 mapping. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | APT33 establishes persistence via Registry Run keys / Startup folder entries for its backdoors (e.g. POWERTON and dropped RATs) per the G0064 mapping. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The actor creates scheduled tasks for execution and persistence of its implants per the G0064 mapping. |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | As Peach Sandstorm, the actor manipulated cloud accounts and tenant configuration to retain access — including registering compromised devices to Azure Arc for cloud-based control and abusing accumulated cloud credentials to preserve access after initial compromise. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Exploitation for Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068/) | APT33 exploits vulnerabilities to escalate privileges on compromised hosts per the G0064 mapping, supporting deeper access and credential theft. |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | As Peach Sandstorm, the actor performed DLL search-order hijacking using legitimate, signed VMware executables to load malicious DLLs, masking execution under a trusted process. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | APT33 encrypts/encodes payloads and configuration to impede static detection per the G0064 mapping, consistent with its use of encoded droppers and packed RATs. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | The actor encodes C2 data using standard encoding schemes (e.g. Base64) in its backdoor communications per the G0064 mapping. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | APT33's backdoors (TURNEDUP, POWERTON) communicate with C2 over HTTP/HTTPS web protocols per the G0064 mapping, blending with normal web traffic. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The actor downloads additional tools and payloads to compromised hosts (stagers pulling RATs/backdoors, later cloud tooling) per the G0064 mapping. |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | The actor uses non-standard ports for C2 communications per the G0064 mapping. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | The actor encrypts C2 traffic with symmetric cryptography per the G0064 mapping, layering encryption over its web channel. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | As Peach Sandstorm, the actor deployed the AnyDesk commercial remote monitoring and management (RMM) tool to maintain interactive remote access to compromised systems. |
| Proxy: Multi-hop Proxy | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | As Peach Sandstorm, the actor routed its password-spray and cloud-access traffic through the TOR onion-routing network to obscure the true source, producing sign-ins from TOR exit nodes. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | As Peach Sandstorm, the actor used the custom EagleRelay tool to tunnel traffic between actor-controlled systems and victim environments, concealing C2 and enabling access to otherwise unreachable internal systems. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery: Cloud Account | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | As Peach Sandstorm, the actor ran AzureHound to enumerate accounts, roles and relationships in Microsoft Entra ID after gaining cloud access, mapping identities for follow-on targeting. |
| Cloud Service Discovery | [T1526](https://attack.mitre.org/techniques/T1526/) | As Peach Sandstorm, the actor used Roadtools and AzureHound to enumerate cloud services and Azure Resource Manager resources accessible to the compromised identity, then dumped data of interest. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | The actor archives collected data using compression utilities prior to exfiltration per the G0064 mapping. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | As Peach Sandstorm, the actor used RDP for hands-on-keyboard lateral movement within compromised environments. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | The actor exfiltrates collected data over an alternative, unencrypted non-C2 protocol per the G0064 mapping. |

## Defense Impairment

| Technique | ID | Notes |
|---|---|---|
| Impair Defenses: Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | In the assessed Shamoon/StoneDrill destructive-attack nexus, the actor disabled or tampered with security tooling and abused a signed low-level disk driver (RawDisk-style) to gain the direct disk access needed to wipe systems, working around endpoint defenses (remapped ID per this dataset's convention). |
| Impair Defenses: Clear Windows Event Logs | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | In destructive operations the actor clears/destroys Windows event logs as part of anti-forensics before or during wiping, reducing host visibility (remapped ID per this dataset's convention; assessed Shamoon-nexus behavior). |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | ASSESSED Shamoon/StoneDrill nexus: destructive malware linked to APT33 members overwrote files and data on targeted Saudi/Gulf energy-sector workstations with random data or image files, rendering them irrecoverable — availability-focused impact distinct from the group's espionage core. |
| Disk Wipe | [T1561](https://attack.mitre.org/techniques/T1561/) | ASSESSED Shamoon/StoneDrill nexus: the wiper malware performed raw disk wiping across networks, propagating with worm-like features using valid accounts and admin shares to maximize availability impact against energy/petrochemical targets. |
| Disk Wipe: Disk Content Wipe | [T1561.001](https://attack.mitre.org/techniques/T1561/001/) | ASSESSED Shamoon/StoneDrill nexus: the malware overwrote arbitrary portions of disk content (via a signed RawDisk-style driver for direct disk access) rendering stored data irrecoverable through the storage interface. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | ASSESSED Shamoon/StoneDrill nexus: the wiper overwrote the Master Boot Record and partition-table structures, leaving thousands of workstations unable to boot — the hallmark Shamoon disk-structure destruction. |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | ASSESSED Shamoon/StoneDrill nexus: destructive operations sought to prevent recovery of corrupted systems, augmenting the disk-wipe impact so that affected hosts could not be restored from built-in recovery features. |
