# Moses Staff — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **28** across **11** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Moses Staff developed custom tooling: the PyDCrypt PyInstaller loader, the DCSrv destructive encryptor built by weaponizing the open-source DiskCryptor driver, and the previously undocumented StrifeWater RAT. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial access is achieved by exploiting known vulnerabilities in external-facing infrastructure, most notably Microsoft Exchange servers (ProxyLogon / ProxyShell) and other public-facing web vulnerabilities. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PyDCrypt attempts to spread the DCSrv payload across the network using PowerShell (alongside PsExec and WMIC) with previously collected administrator credentials. |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | PyDCrypt uses WMIC as one of its lateral spreading/execution mechanisms to deploy DCSrv to remote hosts using compromised administrator credentials. |
| System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | PyDCrypt uses PsExec to remotely execute the DCSrv payload as a service on target machines during network spreading. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | StrifeWater RAT provides command execution via cmd.exe as one of its core operator capabilities on compromised hosts. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | After exploitation the actor drops ASPX web shells onto compromised IIS servers — e.g. IISpool.aspx written to C:\inetpub\wwwroot\aspnet_client\system_web\ — to maintain access and proxy follow-on commands. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | DCSrv establishes persistence by registering Windows services — DCUMSrv (the encryptor service, masquerading as svchost.exe) and DCDrv (the DiskCryptor kernel driver service). |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | StrifeWater RAT persists by creating a scheduled task disguised with a legitimate-looking name, '_Mozilla\Firefox Default Browser Agent 409046Z0FF4A39CB_', to survive reboots. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Moses Staff extensively masquerades tooling with legitimate names: StrifeWater RAT runs as calc.exe, DCSrv masquerades as svchost.exe, and the StrifeWater persistence task impersonates a Firefox browser-agent task. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | To cover its tracks, StrifeWater is replaced with the original Windows calculator binary (copied from system32 to C:\Users\Public) and then deleted; the RAT also supports a self-removal command from its operators. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | PyDCrypt carries the DCSrv payload in encrypted form and decrypts it at runtime before deployment; it is packaged with PyInstaller to hinder static analysis. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Prior to spreading, PyDCrypt collects the domain name and machine names; StrifeWater profiles each host (machine name, username, OS version, timezone, privilege level). |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | PyDCrypt enumerates machine names in the domain to identify targets for lateral spreading of the DCSrv encryptor. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | StrifeWater RAT enumerates files and directories on compromised hosts as one of its reconnaissance capabilities. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | PyDCrypt collects and reuses compromised domain administrator credentials to authenticate to and spread the DCSrv payload across the network via PsExec, WMIC and PowerShell. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | PsExec-based spreading of DCSrv relies on SMB and Windows admin shares (ADMIN$/IPC$) to copy and launch the payload on remote machines. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | PyDCrypt transfers the DCSrv payload to remote hosts as part of its network-spreading routine before executing it. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | StrifeWater RAT captures screenshots of the compromised host and sends them to its command-and-control server. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Consistent with its hack-and-leak model, Moses Staff steals data from compromised systems before deploying destructive encryption, later publishing the stolen data. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | StrifeWater RAT beacons over HTTP to its C2 (techzenspace[.]com / 87.120.8[.]210 on port 80) using URIs such as /RVP/index8.php and /RVP/index3.php, with a configurable default beacon interval of ~20-22 seconds. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | StrifeWater RAT obfuscates its C2 traffic using XOR-based symmetric encryption with a hardcoded key (observed key '9c4arSBr32g6IOni'). |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | StrifeWater RAT downloads additional modules from its C2 (observed module names mainfunc, Ah13, mkb64, strt) to extend functionality on the compromised host. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | In line with its hack-and-leak mission, Moses Staff exfiltrates stolen victim data and publishes it via a dedicated leak website and Telegram channel to maximize reputational and psychological impact. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | DCSrv, built on the open-source DiskCryptor driver, encrypts all available drives (C: through Z:) on infected machines by issuing IOCTL codes (DC_CTL_ENCRYPT_START, DC_CTL_ENCRYPT_STEP) to the DiskCryptor kernel driver. The intent is destruction and disruption, not extortion — no ransom is demanded and no decryption is offered. |
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | Moses Staff's use of encryption is fundamentally destructive: with no decryption capability offered and a flawed encryption implementation, the DCSrv operation renders victim data and systems permanently inaccessible, functionally destroying data rather than holding it for ransom. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | DCSrv overwrites the boot-loader with a custom DiskCryptor bootloader, denying the victim access to the operating system and preventing normal boot — corrupting disk boot structures to render endpoints unusable. |
| System Shutdown/Reboot | [T1529](https://attack.mitre.org/techniques/T1529/) | After encrypting drives and overwriting the boot-loader, DCSrv reboots the machine so it comes up locked behind the DiskCryptor bootloader, finalizing the denial of access. |
