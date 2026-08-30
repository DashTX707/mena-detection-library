# Pioneer Kitten — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **50** across **15** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Search Open Technical Databases | [T1596](https://attack.mitre.org/techniques/T1596/) | Actors use the Shodan search engine (Shodan.io) to identify and enumerate internet infrastructure hosting devices vulnerable to particular CVEs (edge/VPN appliances). |
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Actors conduct mass scanning of IP addresses hosting Palo Alto Networks PAN-OS/GlobalProtect VPN devices (probing for CVE-2024-3400, as of April 2024) and scan IPs hosting Check Point Security Gateways (probing for CVE-2024-24919, as of July 2024). |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Actors operated a Pay2Key .onion (Tor) leak site hosted on cloud infrastructure registered to a previously compromised victim organization, and abuse third-party web services (catbox.moe, ngrok, cloud provider accounts) for hosting and relaying. |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | During the Pay2Key information operation, actors publicized compromises on social media, tagging accounts of victim and media organizations to amplify the hack-and-leak narrative. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Actors obtain and operationalize publicly available tools including Ligolo/ligolo-ng, ngrok, Meshcentral, AnyDesk, and (historically) Mimikatz and Plink. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Signature behavior and primary initial-access vector: exploitation of public-facing networking/VPN/edge devices — Citrix NetScaler (CVE-2019-19781, CVE-2023-3519), F5 BIG-IP (CVE-2022-1388), Pulse Secure/Ivanti Connect Secure (CVE-2024-21887), PAN-OS GlobalProtect firewalls (CVE-2024-3400), and Check Point Security Gateways (CVE-2024-24919). |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Actors create the directory /xui/common/images/ on targeted IP addresses and abuse remote external services on internet-facing assets (VPN/Citrix) to gain and maintain access. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Actors use a compromised admin account to start Microsoft Windows PowerShell ISE and run Invoke-WebRequest with a URI including files.catbox.moe (free file-hosting used as a repository); they also enable servers to use Windows PowerShell Web Access. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Actors deploy webshells on compromised Citrix NetScaler devices to capture login credentials (appended to a file named netscaler.1 in the webshell directory) and maintain access. Observed directories/files: /var/vpn/themes/imgs/ (netscaler.1, netscaler.php, ctxHeaderLogon.php); and, redeployed immediately after victims patch, /netscaler/logon/LogonPoint/uiareas/ui_style.php and /netscaler/logon/sanpdebug.php. Also place the malicious backdoor version.dll in C:\Windows\ADFS\. |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Actors create local accounts on victim networks. Observed account names include "sqladmin$", "adfsservice", "IIS_Admin", "iis-admin", and "John McCain". |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Actors request exemptions to the victim's zero-trust application and security policies for tools they intend to deploy on the network. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Actors create the malicious scheduled task SpaceAgentTaskMgrSHR in the Windows/Spaceport/ task folder; the task uses DLL side-loading against the signed Microsoft SysInternals executable contig.exe (which may be renamed dllhost.ext) to load a payload from version.dll, observed executed from the Windows Downloads directory. A second scheduled task is used to load malware through installed backdoors. |
| Server Software Component | [T1505](https://attack.mitre.org/techniques/T1505/) | For persistence during detection/mitigation, actors create a daily Windows service task named with a random eight-character string and attempt to load a similarly named DLL from C:\Windows\system32\drivers\ (e.g., a service named "test" loading C:\WINDOWS\system32\drivers\test.sys). |
| Event Triggered Execution: Accessibility Features | [T1546.008](https://attack.mitre.org/techniques/T1546/008/) | Fox Kitten has abused Windows accessibility features (e.g. sticky keys) for persistence and privileged execution. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts: Local Accounts | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Actors repurpose compromised credentials harvested from exploited networking devices (e.g., Citrix NetScaler) to log into other applications such as Citrix XenDesktop. |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Actors repurpose administrative credentials of network administrators to log into domain controllers and other infrastructure on victim networks. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Actors use DLL side-loading: the signed SysInternals executable contig.exe (may be renamed dllhost.ext) is abused to load a malicious version.dll payload, launched from the Windows Downloads directory via the SpaceAgentTaskMgrSHR scheduled task. |
| Masquerading: Masquerade Task or Service | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | Actors name malicious scheduled tasks/services to blend in — e.g. the scheduled task SpaceAgentTaskMgrSHR in a Windows/Spaceport/ folder and daily random-eight-character Windows service tasks loading a matching .sys driver. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Actors rename the SysInternals contig.exe to dllhost.ext to masquerade as a legitimate binary, and create accounts with legitimate-looking names (e.g. IIS_Admin, adfsservice, sqladmin$) to blend in. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Fox Kitten obfuscates commands and scripts to hinder analysis and detection. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Fox Kitten encodes/encrypts files and payloads to evade static detection. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | Actors use administrator credentials to disable antivirus and security software, and attempt to enter security-exemption tickets to the network security device or contractor to get their tools allowlisted. |
| Downgrade Attack | [T1689](https://attack.mitre.org/techniques/T1689/) | Actors lower PowerShell policies to a less secure level to enable execution of their scripts. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture | [T1056](https://attack.mitre.org/techniques/T1056/) | Actors capture login credentials on compromised NetScaler devices via a deployed webshell, appending captured credentials to a file named netscaler.1 in the same directory as the webshell. |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Fox Kitten has used credential-dumping tooling including Mimikatz to steal credentials from compromised hosts to enable lateral movement and privilege escalation. |
| OS Credential Dumping: NTDS | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | Fox Kitten has targeted domain-controller credential stores (NTDS.dit) to obtain domain credentials at scale for the domain-admin access they subsequently sell/broker. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Fox Kitten has searched for and harvested credentials stored in files on compromised systems (including credentials captured to files via edge-appliance webshells). |
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Fox Kitten has used brute-force techniques to obtain credentials against exposed services. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Query Registry | [T1012](https://attack.mitre.org/techniques/T1012/) | Actors export system registry hives and network firewall configurations on compromised servers. |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) | Actors exfiltrate account usernames from the victim domain controller and access configuration files and logs to gather network and user-account information for further exploitation. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Fox Kitten scans internal networks to identify services and hosts for lateral movement after gaining a foothold via an exploited edge appliance. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | Fox Kitten enumerates remote hosts on the internal network to plan lateral movement toward domain controllers and high-value systems. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Fox Kitten enumerates files and directories on compromised systems to locate configuration files, credentials and data of interest. |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Fox Kitten enumerates domain accounts (and exfiltrates account usernames from the domain controller) to identify targets for credential theft and access brokering. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Actors use a compromised administrator account to initiate remote desktop sessions to other servers on the network (e.g. to launch PowerShell ISE), and Fox Kitten uses RDP for lateral movement. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Fox Kitten moves laterally using SMB/Windows admin shares (including PsExec-style remote execution) after harvesting credentials. |
| Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Fox Kitten uses SSH (and SSH-tunneling utilities such as Plink) to access and pivot between compromised systems. |
| Exploitation of Remote Services | [T1210](https://attack.mitre.org/techniques/T1210/) | Fox Kitten exploits vulnerabilities in internal remote services to move laterally within compromised environments. |
| Use Alternate Authentication Material: Pass the Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Fox Kitten reuses harvested credential material (including hashes) to authenticate to additional systems. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Cloud Storage | [T1530](https://attack.mitre.org/techniques/T1530/) | Actors leverage compromised cloud-computing resources of victim organizations to conduct further operations, and have used compromised cloud service accounts to transmit data stolen from other compromised organizations. |
| Archive Collected Data: Archive via Utility | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Fox Kitten archives collected data with utilities (e.g. 7-Zip/WinRAR) prior to exfiltration. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Fox Kitten collects sensitive data and files from local systems on compromised hosts (in support of both access-brokering and GOI-aligned data theft). |
| Data from Network Shared Drive | [T1039](https://attack.mitre.org/techniques/T1039/) | Fox Kitten collects data from network shared drives on victim networks. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Actors use PowerShell Invoke-WebRequest to the free online file-hosting site files.catbox.moe as a repository/hosting mechanism to transfer tooling to compromised hosts. |
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | Actors deploy Meshcentral to connect with compromised servers for remote access, and install AnyDesk as a backup access method. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Actors use the open-source tunneling tool Ligolo (ligolo / ligolo-ng) and deploy ngrok (ngrok.io) to create outbound connections to a random subdomain. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Fox Kitten uses proxying/tunneling utilities (including ngrok and open-source tunnelers) to relay C2 and obscure the true source of connections. |
| Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | Actors abuse legitimate web services (e.g. files.catbox.moe file hosting, cloud provider accounts) for hosting, C2 relay and data movement. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service: Exfiltration to Cloud Storage | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Actors use compromised victim cloud-service accounts to transmit/exfiltrate data stolen from other compromised organizations, using victim cloud infrastructure as a relay. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Financial Theft | [T1657](https://attack.mitre.org/techniques/T1657/) | Actors collaborate with ransomware affiliates (NoEscape, RansomHouse, ALPHV/BlackCat) — providing network access, helping lock victim networks, and strategizing on extortion — in exchange for a percentage of ransom payments. They also monetize access by selling full domain control and domain-admin credentials on cyber marketplaces. |
