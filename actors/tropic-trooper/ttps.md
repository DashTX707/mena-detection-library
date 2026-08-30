# Tropic Trooper — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **35** across **14** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Actor probes internet-facing servers for exploitable web applications and CMS/Exchange/ColdFusion vulnerabilities prior to exploitation; public-facing server scanning precedes deployment of the China Chopper web shell. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actor registers and operates espionage C2 domains such as techmersion[.]com (subdomain blog.techmersion[.]com) used for the Crowdoor backdoor's HTTPS command-and-control. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actor develops and maintains custom implants — the Crowdoor loader (a SparrowDoor variant) and updated China Chopper Umbraco web-shell variants carrying defense-evasion improvements — plus historic backdoors ChiserClient and SmileSvr. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Primary initial-access vector: exploitation of a public-facing open-source Umbraco (.NET) CMS web server to plant a China Chopper web shell. Earlier/related intrusions exploited Microsoft Exchange ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207) and Adobe ColdFusion (CVE-2023-26360), and IIS/Exchange servers (Earth Centaur). |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Actor runs commands through the web shell and drops a batch script (i.bat) to perform ICMP ping reconnaissance, writing output to text files for targeting. |
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | The Crowdoor loader resolves and calls native Windows APIs to decrypt (RC4) and execute shellcode in memory and to perform process injection, minimizing on-disk footprint. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Actor executes the loaded payload via a Windows service (service name WinStore), and Fscan/tooling launches remote execution during lateral movement. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Actor deploys a China Chopper variant compiled as a .NET Umbraco CMS module, written as App_Web_{8-char}[a-z0-9].dll into c:\microsoft.net\framework64\v4.0.30319\temporary asp.net files\root\...; the module disables event validation (EnableEventValidation=false) and performs multiple Base64 decodings before generating and executing the final JavaScript payload. Provides durable command execution on the compromised web server; Godzilla/ByPassGodzilla web shells also used. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Crowdoor establishes persistence by creating a Windows service named WinStore that launches the side-loaded loader; if service creation fails it falls back to a registry Run-key ASEP. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Fallback persistence: Crowdoor writes an auto-start extensibility point at HKCU\Software\Microsoft\Windows\CurrentVersion\Run with value name WinStore when service creation is not possible. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Process Injection: Dynamic-link Library Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | The loader injects the decrypted Crowdoor payload into the legitimate Windows binary colorcpl.exe (launched with command-line argument "2") to run under a trusted process context. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Core stealth technique: DLL side-loading / search-order hijacking. Legitimate signed binaries (inst.exe, WinStore.exe) are placed alongside malicious DLLs (VERSION.dll, datast.dll, datastate.dll) dropped to c:\Windows\branding\data and c:\Users\Public\Music\data so the trusted EXE loads the attacker DLL, which RC4-decrypts (key fYTUdr643$3u) and runs the Crowdoor shellcode. datast.dll exports InitCore (older) and Ldf/rcd (updated); datastate.dll exports Clear/Server. |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Crowdoor shellcode is injected into a benign process (colorcpl.exe) to blend malicious network and execution activity with a signed Windows utility and evade image-based detection. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Crowdoor shellcode is stored RC4-encrypted (a stream-cipher variant, key fYTUdr643$3u) inside the malicious DLLs and decrypted at runtime; the Umbraco web shell wraps its payload in multiple layers of Base64 encoding. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime the loader RC4-decrypts embedded shellcode and the web shell performs multiple Base64 decodings before executing the final JavaScript payload. |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Actor names the malicious service and payload WinStore (mimicking Microsoft Store) and drops attacker DLLs named VERSION.dll/datast.dll under legitimate-looking paths such as c:\Windows\branding\data to blend with normal system files. |
| Hide Artifacts: Hidden Files and Directories | [T1564.001](https://attack.mitre.org/techniques/T1564/001/) | Actor stages payloads in obscure data subdirectories (c:\Windows\branding\data, c:\Users\Public\Music\data) to keep implant components out of common inspection paths. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Actor removes intermediate tools and artifacts after use and iterated a new web-shell variant with defense-evasion updates specifically to reduce detection footprint. |
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | The Swor bundle packages ElevationStation and evasion tooling used to bypass endpoint controls; the actor tunes web-shell variants to evade security-product detection during the intrusion. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Actor deploys mimikatz (delivered inside the Swor tool bundle) to dump credentials from LSASS on compromised hosts to enable privilege escalation and lateral movement. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Actor runs Fscan to scan the internal network for live hosts, open ports and services to identify lateral-movement targets after establishing a web-shell foothold. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | Actor uses the i.bat script to perform ICMP ping sweeps enumerating reachable internal hosts, saving results to text files for targeting. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Actor enumerates installed security/AV products on compromised hosts to plan evasion before deploying the Crowdoor loader. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Actor collects host/system information (OS, architecture, configuration) on compromised servers to tailor payloads and side-load targets. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | Actor enumerates network configuration and adjacent hosts on the compromised environment to plan pivoting and proxy placement. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Exploitation of Remote Services | [T1210](https://attack.mitre.org/techniques/T1210/) | Fscan is used both for discovery and to identify/exploit vulnerable internal services, supporting lateral movement across the compromised network. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | After harvesting credentials, the actor moves laterally to additional Windows hosts using SMB/admin-share remote execution to distribute the loader and tooling. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Actor stages reconnaissance and collected data locally — ping-sweep results written to text files and payload/tooling staged in dedicated data directories prior to use and exfiltration. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | Consistent with Earth Centaur tradecraft, the actor collects and archives internal documents (e.g., flight schedules, financial-planning files) and personal data of interest prior to exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Proxy: Internal Proxy | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | Actor deploys Neo-reGeorg as a SOCKS5 web-shell proxy on compromised web servers to tunnel traffic and pivot deeper into the internal network. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Actor uses FRP (fast reverse proxy, delivered via the Swor bundle) and Neo-reGeorg to tunnel command-and-control and internal pivot traffic out of the network. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Crowdoor communicates with its C2 over HTTPS on port 443 to blog.techmersion[.]com; historic Earth Centaur backdoors used HTTP(S) C2 as well. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Crowdoor C2 rides TLS/HTTPS (port 443), wrapping command-and-control in encrypted transport to blend with normal web traffic and resist inspection. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Actor transfers follow-on tooling (Fscan, Swor, Neo-reGeorg, the Crowdoor loader DLLs and side-load host binaries) onto compromised hosts via the web shell and C2 channel. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Actor exfiltrates collected documents and credentials over the established encrypted Crowdoor HTTPS C2 channel, consistent with its espionage objective against the Middle East government target. |
