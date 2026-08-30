# Ballistic Bobcat — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **31** across **13** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Ballistic Bobcat conducts 'scan-and-exploit' behavior — mass scanning the internet for hosts with unpatched, exploitable vulnerabilities (notably Microsoft Exchange) and treating any vulnerable host as an opportunity rather than pursuing pre-selected targets. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | The actor develops and iterates its own Sponsor backdoor across at least five versions (v1-v5, the last aka Alumina), evolving configuration handling, service naming, and evasion between builds. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | The actor obtains and operationalizes publicly available offensive and dual-use tools: Mimikatz, ProcDump, WebBrowserPassView, Host2IP, SharpTShipper, SQLExtractor, Plink, RevSocks, GOST, and Chisel. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Primary initial-access vector: exploitation of internet-facing Microsoft Exchange servers (ProxyLogon/ProxyShell-era, CVE-2021-26855) on already-vulnerable, sometimes already-known-victim hosts, to gain a foothold before dropping the Sponsor backdoor. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Installation and operation are driven by batch scripts (install.bat, Uninstall.bat) executed via cmd.exe; the Sponsor backdoor's 'e' operator command runs arbitrary shell commands with cmd.exe /c. |
| User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | The Sponsor backdoor requires the 'install' runtime argument to execute its installation routine, invoked by the actor's batch-file installer rather than the victim; captured here as the controlled-argument launch behavior of the dropper chain. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | The Sponsor backdoor runs as a registered Windows service; execution of the payload is achieved through the Service Control Manager starting the SystemNetwork/Update service. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Following Exchange exploitation the actor stages files under the Exchange/IIS web root and related paths (e.g. %SYSTEMDRIVE%\inetpub\wwwroot\aspnet_client\, %WINDIR%\INF\MSExchange Delivery DSN\) consistent with webshell-mediated access on the compromised server prior to backdoor installation. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The batch installer registers the Sponsor backdoor as a Windows service configured for automatic startup with full access — named 'SystemNetwork' in v1 and 'Update' in v2 through v5 — providing boot-persistent execution. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts: Local Accounts | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | The actor leverages valid local accounts on compromised hosts (following credential theft) to execute tooling with elevated privileges and to blend backdoor operations with legitimate activity. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Sponsor reads configuration and C2 parameters from on-disk config files (config.txt, node.txt, error.txt) and decodes/decrypts its command-and-control messages (Base64 + RC4) at runtime. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Sponsor stores its operational parameters in obfuscated on-disk configuration files and obfuscates its network traffic; ESET notes evasion improvements across backdoor versions. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | The actor names its service 'SystemNetwork'/'Update' and drops the RevSocks reverse-proxy tool as CSRSS.EXE to masquerade as the legitimate Windows Client/Server Runtime Subsystem; tooling is staged in Windows-legitimate paths such as %WINDIR%\Tasks\ and %WINDIR%\INF\. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | The Sponsor backdoor's 's' operator command runs Uninstall.bat to remove the backdoor and its artifacts from disk, cleaning up indicators when the operator ends access. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | The actor deploys ProcDump (procdump64.exe) to dump LSASS process memory and Mimikatz (mi.exe) to extract credentials from that memory / the local system. |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | The actor runs WebBrowserPassView to extract stored credentials from web browsers on compromised hosts. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | On check-in, the Sponsor backdoor collects extensive host information: hostname, BIOS info, processor details, Windows version, domain membership, username, and AC/battery power status. |
| System Location Discovery: System Language Discovery | [T1614.001](https://attack.mitre.org/techniques/T1614/001/) | The Sponsor backdoor collects the host timezone and locale/language settings as part of its initial reconnaissance report to the C2. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The Sponsor backdoor's 'p' operator command returns a process ID to the operator, providing basic process-context discovery. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | The actor runs Host2IP (host2ip.exe) to resolve hostnames to IP addresses and map remote systems on the victim network in preparation for lateral movement and tunneling. |
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Following the Host2IP mapping, the actor identifies reachable internal services/hosts to plan pivoting and tunneling deeper into the network. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | The actor uses Plink (the PuTTY command-line SSH client) to establish SSH connections/tunnels for pivoting between and accessing compromised systems. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | The actor uses SQLExtractor (sqlextractor.exe) to interact with and extract data from SQL databases on compromised hosts, and collects local host data via the backdoor. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The Sponsor backdoor communicates with its C2 over HTTP on port 80, polling at a configurable interval defined in config.txt. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | Sponsor encrypts its C2 message contents with RC4 (a symmetric cipher) before transmission over HTTP. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | Sponsor Base64-encodes its (RC4-encrypted) C2 messages before sending them over HTTP. |
| Data Obfuscation | [T1001](https://attack.mitre.org/techniques/T1001/) | Sponsor obscures its command-and-control traffic by layering RC4 encryption and Base64 encoding, disguising the true content of operator commands and exfiltrated host data. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The Sponsor backdoor's 'd' and 'u' operator commands download and execute additional files, with 'u' using the URLDownloadToFileW API; dedicated tool-delivery servers were used to stage the open-source toolset. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | The actor deploys RevSocks (as CSRSS.EXE) and GOST to establish reverse SOCKS proxies / TCP-UDP relays out of the victim network, and Chisel for HTTP/SSH-tunneled proxying. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | The actor uses Plink (plink.exe) for SSH tunneling and GOST/Chisel to tunnel TCP/UDP/HTTP traffic, relaying connections to bypass network controls and reach internal systems. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected host reconnaissance and command output are returned to the operator over the same Base64+RC4-obfuscated HTTP/80 Sponsor C2 channel. |
