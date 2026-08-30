# Stealth Falcon — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **36** across **10** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Operators created fake personas and social-media accounts — including a fictitious journalist 'Andrew Dwight' and front organizations ('The Right to Fight') — and used Twitter mentions to deliver malicious tracking links to targeted Emirati activists and journalists, building rapport over multiple months before delivery. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Operators established email accounts tied to fictitious organizations and personas to send pretext emails offering speaking opportunities or collaboration, delivering aax.me tracking links and macro documents. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors registered numerous C2 and staging domains, many deliberately masquerading as CDN/cache/search/ad services (e.g. incapsulawebcache[.]com, edgecacheimagehosting[.]com, windowsearchcache[.]com, adhostingcache[.]com, upnpdiscover[.]org) to blend malicious callbacks with benign-looking web traffic. |
| Stage Capabilities: Link Target | [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | Actors operated a custom URL-shortener/profiling service at aax.me (link regex /aax.me/[0-9a-f]{5}/) with administrative access enabling specialized per-target tracking links; the shortener ran JavaScript visitor-profiling (browser, plugins, timezone, installed AV via port-timing, Tor detection) before redirecting to bait content. Over 402 aax.me links were identified, ~73% referencing UAE political issues. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | The group developed bespoke malware rather than using off-the-shelf frameworks — a custom two-stage PowerShell backdoor (2016) and the Win32/StealthFalcon BITS-abusing backdoor (analyzed 2019) — indicating an in-house development capability. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Primary delivery vector: spear-phishing links delivered via Twitter mentions and pretext emails, routed through the aax.me tracking shortener that profiled the recipient before redirecting. Links were individually crafted per target following months of social engineering. |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Follow-on delivery used macro-enabled Word documents (.docm — e.g. right2fight.docm, message_032456944343.docm) attached to pretext emails, displaying a spoofed Proofpoint security warning to coax the target into enabling macros. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Successful compromise depended on the target clicking the aax.me tracking link, which profiled the browser and redirected toward malicious/bait content. |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | The target opened the malicious .docm and enabled macros (prompted by the spoofed Proofpoint warning), triggering the macro that launched the PowerShell backdoor chain. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | A VBScript loader (IEWebCache.vbs) containing Base64-encoded PowerShell was written to disk and executed by a scheduled task to launch the backdoor stages. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | The core implant is a bespoke two-stage PowerShell backdoor; Stage One performs system profiling and .NET version detection, later stages handle C2 and tasking. Win32/StealthFalcon is likewise a PowerShell-based implant. |
| Command and Scripting Interpreter: JavaScript | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | The aax.me tracking page ran JavaScript to profile the visitor (ActiveX/Flash/Java/Office detection, AV port-probing via XMLHttpRequest timing, timezone/plugin/user-agent enumeration, Tor-browser deanonymization attempts) before redirecting. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | Stage One of the PowerShell backdoor used WMI to detect the installed .NET Framework version and gather system-profiling information to select the appropriate follow-on payload. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The 2016 implant created a scheduled task named 'IE Web Cache' executing hourly to run the VBS/PowerShell loader. The Win32/StealthFalcon backdoor DLL schedules itself as a task running at each user login for persistence. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Win32/StealthFalcon stores its configuration in HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Shell Extensions under values prefixed with the malware filename — including -MRUData/-MRUList (RC4-encrypted C2 domains), -FontDisposition (victim ID), -IconDisposition (C2 selection flag), -IconPosition (sleep interval), and -PopupPosition (failed-connection counter). |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Configuration data and C2 domains are RC4-encrypted in the registry, and the VBS loader carries Base64-encoded PowerShell — payloads and config are stored encoded/encrypted to evade static inspection. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | The VBScript loader embeds Base64-encoded PowerShell that is decoded and executed at runtime, obscuring the command payload from casual inspection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime the backdoor RC4-decrypts its registry-stored C2 configuration and the loader Base64-decodes its embedded PowerShell before execution. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Actors named their scheduled task 'IE Web Cache' and VBS loader IEWebCache.vbs, and registered C2 domains masquerading as legitimate CDN/cache/search/discovery services (windowsearchcache[.]com, incapsulawebcache[.]com, edgecacheimagehosting[.]com, upnpdiscover[.]org) so tasks and callbacks blend with benign activity. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Stealth Falcon tooling has capability to steal credentials saved in web browsers on compromised hosts. |
| Credentials from Password Stores: Windows Credential Manager | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | Stealth Falcon tooling has capability to steal credentials stored in the Windows Credential Manager / Vault. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Query Registry | [T1012](https://attack.mitre.org/techniques/T1012/) | The backdoor reads its encrypted configuration (C2 domains, victim ID, sleep interval, failure counter) back from its HKCU Shell Extensions registry values on each execution cycle. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | The aax.me profiling JavaScript fingerprinted installed antivirus by probing product-specific localhost ports via XMLHttpRequest timing (e.g. 12993 Avast, 44080 Avira, 1110 Kaspersky, 6646 McAfee, 6999 Trend Micro, 30606 ESET) to tailor delivery and evade detection. |
| Software Discovery | [T1518](https://attack.mitre.org/techniques/T1518/) | The profiling stage enumerated installed browser plugins and software versions (ActiveX, Flash, Java, Microsoft Office) via JavaScript/ActiveX detection to select an appropriate payload and lure. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Stage One of the backdoor gathered system information (including .NET Framework version via WMI) to profile the host and choose the correct follow-on payload. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | The backdoor collects network configuration details from the compromised host as part of its reconnaissance and C2-setup routine. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | The backdoor enumerates the current user/owner of the compromised system during profiling. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The backdoor enumerates running processes on the host as part of environment reconnaissance and tasking. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Automated Collection | [T1119](https://attack.mitre.org/techniques/T1119/) | The backdoor automatically collects system data and information of interest from the compromised host as part of its standing tasking, without per-item operator interaction. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | The backdoor collects files and data from the local system on compromised hosts belonging to targeted journalists, activists and dissidents. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| BITS Jobs | [T1197](https://attack.mitre.org/techniques/T1197/) | Signature behavior of Win32/StealthFalcon: the backdoor abuses the Windows Background Intelligent Transfer Service (BITS) to communicate with its C2 servers and exfiltrate data, rather than standard socket APIs — BITS traffic is often ignored by firewalls and security products, providing stealthy, resilient transport. (ATT&CK maps BITS Jobs to defense-evasion/persistence; placed here to reflect its observed C2/exfil function and Stage-2 detect routing.) |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | C2 is conducted over HTTP(S) web protocols (carried via BITS transfers) to attacker domains that masquerade as CDN/cache services. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | C2 communications and stored configuration are protected with RC4 symmetric encryption using hardcoded keys, obscuring traffic content and the C2 domain list. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The staged architecture retrieves follow-on payloads/tasking (Stage Two) from C2 infrastructure after Stage One profiling, transferring additional code to the compromised host. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Collected data is exfiltrated over the same BITS/HTTP C2 channel used for tasking, back to the attacker-controlled masquerading domains. |
| Automated Exfiltration | [T1020](https://attack.mitre.org/techniques/T1020/) | Exfiltration of collected host data is automated through the BITS-based backdoor on its C2 polling cycle (governed by the registry-stored sleep interval), without per-transfer operator action. |
