# Predatory Sparrow — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **34** across **12** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Host Information | [T1592](https://attack.mitre.org/techniques/T1592/) | Toolchain artifacts reveal detailed prior knowledge of the victim environment before deployment — a hardcoded internal path (\\railways.ir\sysvol\railways.ir\scripts\env.cab), awareness of domain-controller configuration, and knowledge of Veeam backup infrastructure — indicating substantial pre-attack reconnaissance of hosts and infrastructure. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | The Meteor wiper is an externally configurable, purpose-built destructive tool assessed to have been in development for roughly three years, mixing custom code with open-source components and heavy sanity/error-checking; its configurability shows it was built for reuse beyond a single operation (consistent with the related Stardust/Comet variants). |
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | The actor operates a public 'Gonjeshke Darande / Predatory Sparrow' Telegram (and other social) presence used to claim operations, publish 'proof' CCTV footage of the steel-plant sabotage, and release exfiltrated documents in hack-and-leak fashion. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | For the fuel-station operations the actor reportedly obtained access to a central management / technical-support server for the fuel-pump software and operated with valid/privileged access to reach downstream stations; the railway operation likewise deployed malware using existing domain privileges. |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | Reporting on the fuel-station campaigns indicates the actor reached large numbers of stations by compromising the shared central management/technical-support system that operates the fuel-pump software, i.e. abusing a trusted upstream provider relationship to fan out to downstream operators. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | A VBScript dropper (resolve.vbs) is used to stage/execute the destructive toolchain and deploy the password-protected RAR archives. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The operation is orchestrated by a chain of batch scripts — setup.bat (GPO entry / clears the 'AnalyzeAll' task / stages from a network CAB), update.bat (creates mutex lockfile C:\Windows\Temp\__lock6423900.dat and extracts three RAR archives with password 'hackemall'), cache.bat, bcd.bat and msrun.bat — each invoking native destructive utilities. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | cache.bat uses PowerShell to disable network adapters (isolating the host from remediation) and to create Windows Defender exclusions before the destructive payload runs. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | The Meteor toolchain uses WMI (wmic) redundantly alongside native APIs to delete shadow copies and to remove the host from its domain, ensuring the destructive actions complete even if one method fails. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | msrun.bat creates a scheduled task named 'mstask' set to execute the Meteor wiper at 23:55 (a delayed, synchronized detonation); the toolchain also deletes a pre-existing scheduled task named 'AnalyzeAll' as part of setup. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | Payloads are shipped inside password-protected RAR archives (programs.rar, bcd.rar, ms.rar; password 'hackemall'), and the Meteor configuration (msconf.conf) is encrypted; logs/config are protected with an XOR key ('abcdz'), hindering static analysis. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | The Meteor wiper modifies the registry to disable the screensaver, alter boot-policy error handling, and set the lock-screen image (per-OS variants), reinforcing the screenlocker denial effect and the boot sabotage. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Destructive components are named to blend into a Windows environment (env.exe/msapp.exe for the wiper, mssetup.exe for the screenlocker, mstask scheduled task, mscap.bmp/mscap.jpg wallpaper), imitating legitimate 'ms*' system naming. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | Before detonation the toolchain creates Windows Defender exclusions via PowerShell and branches on the presence of Kaspersky, impairing local defences so the destructive components run unhindered. (Bundled-dataset normalization: public MITRE T1562.001 -> T1685.) |
| Clear Windows Event Logs | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | bcd.bat uses wevtutil to clear the Security, System and Application event logs, destroying forensic evidence of the intrusion as part of the destructive sequence. (Bundled-dataset normalization: public MITRE T1070.001 -> T1685.005.) |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Toolchain components are cleaned up / self-deleted immediately after execution to remove forensic artifacts, complicating post-incident recovery of the full malware set (nti.exe was never recovered). |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | cache.bat checks for the presence of Kaspersky antivirus and aborts/branches if it is found, tailoring execution to the host's security posture. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | The encrypted Meteor configuration (msconf.conf) contains a configurable 'processes_to_kill' list, which the wiper enumerates and terminates prior to/while wiping to free file handles and disable defences. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | The toolchain fingerprints the host OS version to select the correct components — a separate envxp.bat path for legacy Windows XP systems and distinct lock-screen images for XP/7/10 — indicating per-OS branching. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Domain Policy Modification: Group Policy Modification | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | Once inside the network the actor used Active Directory Group Policy to distribute and execute the wiper toolchain across many domain-joined hosts simultaneously — the mechanism that turned a single foothold into an organisation-wide destructive event. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | In the June 2022 steel-plant operation the actor collected sensitive documents and 'top secret' files from compromised systems prior to the destructive/leak phase, later publishing them as evidence of IRGC affiliation. |
| Email Collection | [T1114](https://attack.mitre.org/techniques/T1114/) | The steel-plant operation exfiltrated tens of thousands of internal emails from the targeted companies, which the actor subsequently leaked. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | setup.bat stages components by copying them from a network CAB file (env.cab on the railways SYSVOL share) and update.bat unpacks the RAR archives locally, transferring the full toolchain onto each target host from an internal staging point. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Stolen documents, emails and 'proof' CCTV footage are exfiltrated and published through the actor's Telegram/social channels in a hack-and-leak model rather than exfiltrated to private infrastructure. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | The Meteor wiper destroys the filesystem, wiping the paths enumerated in its encrypted configuration ('paths_to_wipe'); in the June 2025 Nobitex operation the actor destroyed ~$90M in crypto by sending it to provably unspendable 'burn' addresses, a destruction-not-theft impact. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | A dedicated component (nti.exe) overwrites the Master Boot Record — reportedly the same sectors targeted by NotPetya — rendering the machine unbootable independently of the filesystem wipe. |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | The toolchain deletes Volume Shadow Copies (vssadmin 'delete shadows /all /quiet' and redundant wmic), corrupts boot configuration with bcdedit and overwrites boot.ini with impossible partition numbers (10000000), and flushes cache with SysInternals Sync — collectively preventing recovery and reboot. |
| Defacement: Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) | The actor defaced internal victim-controlled display systems — railway station arrival/departure boards (instructing passengers to call '64411', Khamenei's office) in July 2021 and roadside/fuel-station digital billboards ('Khamenei, where is our fuel?') in the October 2021 fuel operation — for psychological/propaganda effect. |
| Data Manipulation: Runtime Data Manipulation | [T1565.003](https://attack.mitre.org/techniques/T1565/003/) | Nearest-Enterprise mapping of the steel-plant OT/ICS impact: the actor manipulated the production-control plane (HMI/PLC layer) at Khuzestan Steel to drive an overhead crane/ladle to spill molten metal onto the factory floor — a runtime manipulation of the industrial process producing physical damage and fire. (ATT&CK-for-ICS 'Manipulation of Control' has no Enterprise equivalent in the bundled dataset; mapped to the nearest present technique.) |
| Service Stop | [T1489](https://attack.mitre.org/techniques/T1489/) | The fuel-station operations disabled the pump payment/control services (roughly 70% of stations offline in Dec 2023, forcing manual operation); the railway toolchain also disconnected network adapters and terminated configured processes to halt services. |
| Endpoint Denial of Service | [T1499](https://attack.mitre.org/techniques/T1499/) | The screenlocker component (mssetup.exe) locks the user out of the workstation with a replacement lock screen (mscap.bmp/mscap.jpg wallpaper), denying interactive access as part of the destructive campaign. |
| Account Access Removal | [T1531](https://attack.mitre.org/techniques/T1531/) | The Meteor wiper changes user passwords, removes the host from its domain (via WinAPI and WMI redundantly), and logs off local sessions — cutting administrators off from the machines and preventing quick remediation from the domain controller. |
| System Shutdown/Reboot | [T1529](https://attack.mitre.org/techniques/T1529/) | After corrupting boot configuration and wiping, the toolchain forces the system into an unbootable reboot state, completing the denial effect and maximizing downtime. |
| Financial Theft | [T1657](https://attack.mitre.org/techniques/T1657/) | In June 2025 the actor destroyed banking data at state-owned Bank Sepah and drained/burned roughly $90M from the Nobitex crypto exchange to unspendable vanity addresses — financially themed impact motivated by disruption/message rather than profit. |
