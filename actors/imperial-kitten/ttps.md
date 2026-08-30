# Imperial Kitten — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **35** across **12** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | Actors used public scanning tools such as nmap to identify exposed services and hosts of interest. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Compromise Infrastructure: Server | [T1584.004](https://attack.mitre.org/techniques/T1584/004/) | Actors compromised legitimate Israeli websites/servers and used them as watering holes, embedding malicious JavaScript to profile visitors before staging follow-on payloads. |
| Stage Capabilities: Drive-by Target | [T1608.004](https://attack.mitre.org/techniques/T1608/004/) | Actors staged malicious JavaScript on compromised Israeli sites, in several cases delivered/profiled via the Matomo analytics platform and CDN-mimicking domains, to fingerprint visitors and deliver drive-by content to selected targets. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors registered numerous CDN/analytics-masquerading domains (e.g. jquery-cdn.online, cdn.jguery.org, cdn-analytics.co, fastanalytics.live, hotjar.info) to host watering-hole scripts, profiling beacons and second-stage infrastructure. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Actors created attacker-controlled Yandex webmail accounts (and update-platform-check.online mailboxes) used as IMAP command-and-control endpoints for IMAPLoader and StandardKeyboard. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actors developed custom .NET implants (IMAPLoader, StandardKeyboard) and predecessor Python IMAP implants, iterating on injection technique (AppDomainManager injection derived from the 2020 GhostLoader PoC). |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Consistent with the cluster's long-running fake-persona social engineering (TA456/Tortoiseshell tradecraft), actors maintain fabricated recruiter/professional personas used to build rapport and deliver CV/recruitment-themed lures to targets. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Signature initial-access vector: strategic web compromise (watering hole). Victims visiting compromised legitimate Israeli websites were fingerprinted by injected JavaScript (public IP, browser/screen data) and, if of interest, delivered follow-on content leading to implant deployment. |
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Actors gained access using public one-day exploits and SQL injection against internet-facing applications of target organizations. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Actors used stolen VPN credentials to authenticate to victim remote-access services and obtain initial network access. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Actors delivered phishing emails carrying malicious Office documents, including macro-enabled Excel workbooks and CV/recruitment-themed lures aligned with fake-persona social engineering. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Delivery relied on the victim opening a weaponized Excel workbook and enabling macros, which executed the embedded VBA to drop and run a Python reverse shell. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Malicious Excel lures used embedded VBA macros to stage and launch the next-stage Python reverse shell on execution. |
| Command and Scripting Interpreter: Python | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | A Python reverse shell was dropped by the macro-enabled Excel lure and executed to provide interactive command execution and callback to actor infrastructure. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Post-exploitation actions used the Windows command shell to run reconnaissance, deploy tooling (PAExec, NetScan, ProcDump) and stage implants. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Actors established persistence via Registry Run keys to auto-execute their implants at logon. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Actors created scheduled tasks to persist and periodically execute their implants. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The StandardKeyboard implant was installed and persisted as a Windows Service (e.g. WindowsServiceLive.exe), running with SYSTEM privileges and re-launching after reboot. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Hijack Execution Flow: AppDomainManager | [T1574.014](https://attack.mitre.org/techniques/T1574/014/) | IMAPLoader uses AppDomainManager injection (a technique first demonstrated in the 2020 GhostLoader PoC) to load its .NET payload into a benign host process, circumventing tools that watch for classic DLL/EXE loading on Windows. |
| Process Injection: Dynamic-link Library Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | IMAPLoader injects its .NET DLL payload into a host process (via the AppDomainManager mechanism) so that malicious code runs under the context of a legitimate process. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Actors masqueraded infrastructure and files as legitimate CDN/analytics services (jquery-cdn.online, cdn.jguery.org, hotjar.info) and named implant service binaries innocuously (e.g. WindowsServiceLive.exe) to blend in. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Implants and delivery scripts (VBA/Python, .NET payloads) were obfuscated/encoded to hinder static detection and analysis. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Actors used ProcDump to dump LSASS process memory and harvest credentials for reuse and lateral movement. |
| Unsecured Credentials | [T1552](https://attack.mitre.org/techniques/T1552/) | Actors harvested and reused stolen credentials (including VPN credentials) obtained from compromised hosts to expand access. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | After gaining a foothold, actors ran NetScan (SoftPerfect) and nmap internally to enumerate hosts and services for lateral movement. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Implants and hands-on-keyboard activity enumerated host details (system, network and browser/visitor information) to profile victims and select high-value targets. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | Actors transferred tooling (PAExec, NetScan, ProcDump, implants) across the network to additional hosts during lateral movement. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Actors used PAExec (a PsExec alternative) to execute code remotely over SMB/admin shares and move laterally after harvesting credentials. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Actors collected files and data of interest from compromised hosts for espionage purposes. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Mail Protocols | [T1071.003](https://attack.mitre.org/techniques/T1071/003/) | Signature C2 mechanism: IMAPLoader and StandardKeyboard communicate over IMAP email, polling attacker-controlled Yandex (and update-platform-check.online) mailboxes for tasking and retrieving payloads/results as email content — using legitimate mail infrastructure as the channel. |
| Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | A Discord-based RAT variant used Discord as a C2/relay channel, and watering-hole profiling abused the Matomo analytics service as an intermediary for visitor data. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | Actors deployed MeshAgent (MeshCentral) to maintain interactive remote access to compromised hosts. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Some implants and the watering-hole beacons communicated over HTTP/HTTPS to hardcoded actor infrastructure (CDN/analytics-masquerading domains and VPS IPs). |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Implants retrieved additional payloads/tooling from actor infrastructure — including next-stage payloads pulled as IMAP email attachments/content and downloads from hardcoded domains/IPs. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Stolen data and command output were exfiltrated back through the implants' C2 channels — notably as IMAP email content to attacker-controlled mailboxes and via the Discord/HTTP channels. |
