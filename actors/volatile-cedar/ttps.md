# Volatile Cedar — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium-high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **30** across **11** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Active Scanning: Vulnerability Scanning | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Actors scan internet-facing web servers for exploitable weaknesses (SQL-injectable parameters and known-vulnerable Atlassian/Oracle software versions) as the front of their public-web-server intrusion model. ClearSky observed selection of unpatched Confluence, Jira and Oracle 10g servers, indicating version/vulnerability probing at scale (~250 servers breached). |
| Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Actors sweep internet IP space to discover exposed web/application servers running vulnerable Atlassian and Oracle products before targeting them, consistent with the opportunistic, internet-wide server-selection model described by both Check Point and ClearSky. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | The group develops and maintains its own custom Explosive RAT codebase (versions 1.x through 4.x) — it is the only known APT to use Explosive. The RAT is deliberately split into a main binary and a separate DLL so operators can quickly patch/update functionality and evade heuristic detection. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register and operate hardcoded static updater C2 domains (e.g. edortntexplore[.]info) plus a pool of DGA-generated domains used as dynamic update servers for Explosive fallback communications. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Signature initial-access vector: compromise of public-facing web/application servers. In the original campaign this was primarily SQL injection against vulnerable web servers; in the 2020–2021 resurgence the group exploited known 1-day vulnerabilities on unpatched internet-facing Atlassian Confluence (CVE-2019-3396), Atlassian Jira (CVE-2019-11581) and Oracle 10g (CVE-2012-3152) servers to gain code execution and plant a web shell. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Actors run operating-system commands through the deployed web shell (and via the Explosive implant) to enumerate the host and network and to install/execute further tooling on the compromised server. |
| Shared Modules | [T1129](https://attack.mitre.org/techniques/T1129/) | Explosive is architected as a main binary plus a separate DLL that provides its API/functionality; the loader binary loads this companion module at runtime, letting operators patch the DLL independently to update capability and dodge heuristic detection. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | After exploiting a public-facing server, actors drop a JSP web shell and, in the 2020–2021 campaign, the Caterpillar WebShell — a modified JSP file-browser derived from the ASPXSpy web shell — to maintain access, browse the filesystem, run commands and stage the Explosive implant. The web shell was found on the majority of investigated victims (~250 breached servers). |
| Hijack Execution Flow: DLL | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | The Explosive implant relies on a paired DLL for its core API activity, loaded by the main binary; this modular DLL design is used both for functionality and to keep the malicious code in a separately updatable module that can be swapped to evade signature detection. (Env note: mapped to T1574.001 'DLL'; T1574.002 side-loading is absent in this dataset.) |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Explosive employs obfuscation to hinder analysis and evade heuristic AV detection; combined with the modular main-binary/DLL split, operators repeatedly re-obfuscate and patch the implant to stay ahead of signatures. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | The Explosive implant decodes/decrypts its obfuscated components and C2 payloads at runtime to execute functionality, complementing its static obfuscation and communication encryption. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) | Post-exploitation, operators harvest credentials from compromised hosts to enable lateral movement and pass-the-hash across the network. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | Operators run ipconfig (and equivalent commands) via the web shell to map the compromised host's network configuration and identify reachable segments. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | Operators run whoami via the web shell to determine the security context/privileges of the compromised service account. |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Operators run net group commands via the web shell to enumerate domain groups and identify privileged accounts/high-value targets within the compromised environment. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | The web shell and Explosive implant gather host information (OS, hostname, system details) to profile the compromised server and tailor follow-on activity. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | Actors use the Caterpillar WebShell's file-browser functionality to enumerate the filesystem of the compromised server, locating configuration files, credentials and data of interest. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | After establishing a foothold on a public-facing server, operators enumerate other reachable internal hosts to plan lateral movement toward high-value systems. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Use Alternate Authentication Material: Pass the Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Operators reuse harvested credential material (hashes) to authenticate to additional systems and traverse network segments after compromising the initial public-facing server. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Operators use PsExec (SMB/admin-share remote execution) to run code on additional hosts and move laterally within the compromised environment. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | Operators move the Explosive implant and supporting tooling from the initially compromised web server to other internal hosts during lateral movement. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | The Explosive RAT includes a keylogging capability, capturing keystrokes on the compromised host and exfiltrating them to the C2 for credential and intelligence collection. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | The Explosive RAT can capture screenshots of the victim's desktop and send them to the C2 as part of its surveillance/collection functionality. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Operators collect files and data of interest from the compromised server/host, both via the Caterpillar WebShell file-browser and via the Explosive implant, for espionage exfiltration. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Captured keystrokes, screenshots and collected files are staged locally on the compromised host prior to HTTP exfiltration to the Explosive C2. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The Explosive RAT communicates with its command-and-control servers over HTTP(S). Beacons use a distinctive/hardcoded HTTP User-Agent and structured URI pattern (e.g. Kaspersky observed check-ins to the static C2 edortntexplore[.]info at URI /micro/data/index.php?micro=4 over port 443), providing a recognizable network signature. |
| Fallback Channels | [T1008](https://attack.mitre.org/techniques/T1008/) | Explosive uses hardcoded static updater C2 servers as its primary channel; when the implant cannot reach its hardcoded static C2, it falls back to a DGA and cycles through dynamically generated domains to re-establish communications. |
| Dynamic Resolution: Domain Generation Algorithms | [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Explosive's control network includes DGA-based dynamic update servers; when the static/hardcoded C2 is unavailable the implant algorithmically generates candidate domains to locate live infrastructure (the DGA infrastructure was sinkholed by Kaspersky). |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Explosive includes a self-update mechanism: it retrieves updated binaries/DLLs from static and DGA-based update servers, letting operators refresh the implant to add functionality and evade detection. |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | Explosive v4 encrypts its command-and-control communications (one of several evasion techniques ClearSky attributes to the RAT) to hinder network inspection and content-based detection. |
