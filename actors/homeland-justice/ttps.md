# Homeland Justice — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **34** across **13** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | The actor operates the 'Homeland Justice' public persona — a Telegram channel and leak website — established to claim responsibility, message victims, and publish stolen Albanian government data. The Karma brand is used analogously in the Israel-context Void Manticore operations. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial access ~14 months before the destructive attack was obtained by exploiting an internet-facing Microsoft SharePoint server via CVE-2019-0604, a .NET deserialization RCE in SharePoint. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Over the ~14-month dwell the actor repeatedly re-entered the environment using RDP and VPN access with compromised accounts, including logging in to a victim print server over RDP to stage the encryption component. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The actor used batch scripts executed via cmd.exe — win.bat (#1 to run the malware, #2 to set the wallpaper) and bb.bat (a taskkill loop terminating a hardcoded process list) — to orchestrate the destructive stage. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Microsoft observed the actor using PowerShell and remote-execution tooling during the intrusion to run commands and move tooling across the Albanian government network. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | The actor deployed .aspx web shells — ClientBin.aspx, which contains a Base64-encoded .NET executable (App_Web_bckwssht.dll) it decodes and loads — on the compromised SharePoint/IIS server to maintain access and proxy follow-on commands. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | The CHIMNEYSWEEP backdoor and follow-on tooling in the MOIS toolset establish persistence via scheduled tasks; Microsoft reporting on the Albania intrusion notes scheduled-task-based execution for maintaining foothold. |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | win.bat was configured to launch the ROADSWEEP payload GoXml.exe (from C:\ProgramData\Microsoft\Windows\GoXml.exe) at system startup, ensuring the destructive component ran on boot. |
| Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | The No-Justice wiper (cl.exe) loads rwdsk.sys, a legitimate EldoS Corporation RawDisk commercial driver, installed/loaded as a kernel service to obtain raw block-level access to the hard drive for wiping (bring-your-own-vulnerable/abusable-driver). |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | The ClientBin.aspx web shell embeds a Base64-encoded .NET executable (App_Web_bckwssht.dll) which it decodes at runtime; the DLL in turn extracts a secondary Base64-encoded 'EncryptionDLL' (Base64.dll) loaded via Assembly.Load — layered encoding to hide the payload from static inspection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | The web shell decodes its Base64-encoded .NET payload and dynamically loads it, and further decodes a secondary Base64 EncryptionDLL at runtime via Assembly.Load — runtime deobfuscation to defeat static detection. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | The ROADSWEEP payload was staged as GoXml.exe under C:\ProgramData\Microsoft\Windows\, placing the destructive binary in a Microsoft-looking directory path to blend with legitimate system content. |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | win.bat (#2) writes the HKCU\Control Panel\Desktop\Wallpaper registry value to point at a Homeland Justice message image (goxml.jpg) and forces a per-user parameter refresh via RUNDLL32 user32.dll,UpdatePerUserSystemParameters. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Impair Defenses: Disable or Modify Tools | [T1685](https://attack.mitre.org/techniques/T1685/) | The actor ran disable_defender.exe, a PE that elevates and disables Windows Defender (manipulating Defender/SmartScreen via smartscreen.exe context) to clear the way for the ransomware and wiper without AV interference. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) | Microsoft observed credential theft during the intrusion, enabling the actor to obtain and reuse valid accounts for RDP/VPN access and lateral movement across the Albanian government network over the long dwell time. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Microsoft reporting notes network scanning during the intrusion (e.g. Advanced Port Scanner) to enumerate reachable hosts and services ahead of lateral movement and the destructive stage. |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | The actor enumerated remote hosts across the government network to identify servers (print server, database and file servers) targeted for encryption and wiping during the long pre-attack dwell. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | The ROADSWEEP encryption component enumerates files and directories on target hosts to select content for encryption, and the wiper enumerates volumes/files for destruction. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | For the encryption stage the actor logged in to a victim organization print server via RDP and used it as a distribution point, and used RDP with compromised accounts to move laterally to targeted servers. |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | The actor staged and distributed the destructive payloads to multiple hosts from a central server (using the print server as a distribution point), consistent with SMB/admin-share-based spreading of GoXml.exe and the batch scripts before mass execution. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | The actor transferred the destructive tooling (GoXml.exe, cl.exe, win.bat, bb.bat, disable_defender.exe) from the compromised distribution host to target machines across the network prior to detonating the encryption and wipe. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Prior to the destructive stage the actor collected sensitive Albanian government data from compromised systems, which was later leaked publicly through the Homeland Justice persona as part of the hack-and-leak operation. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | Stolen government data was aggregated and archived for staged public release across successive Homeland Justice Telegram/leak-site postings, consistent with archiving collected data prior to exfiltration. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | The ClientBin.aspx / App_Web_bckwssht.dll web shell accepts HTTP POST requests carrying a Base64-encoded IP and port and opens a second socket to the supplied address — a web-protocol-fronted command-and-control / relay channel. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Follow-on tooling and destructive payloads were brought into the environment over the long dwell via the web shell and remote-access channels for staging before the July 2022 attack. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | The web shell's socket-relay capability (open a second socket to an attacker-supplied IP:port) provided a channel to move stolen government data out of the environment for later publication via the Homeland Justice persona. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Service Stop | [T1489](https://attack.mitre.org/techniques/T1489/) | Before encryption, bb.bat runs a taskkill loop (@for %C in (%PrcLst%) do @taskkill /f /im "%C.exe") to force-terminate a hardcoded list of processes — unlocking database/application files so the ROADSWEEP encryptor can access and encrypt them. |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | The destructive script executes @vssadmin.exe delete shadows /all /quiet to delete all Volume Shadow Copies, preventing restoration before the ransomware/wiper renders systems unrecoverable. |
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | The ROADSWEEP ransomware (GoXml.exe), launched by win.bat with the arguments '1 2 3 4 5 6 7', encrypts files on targeted hosts and drops a ransom/message note as part of the destructive operation against the Albanian government. |
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | Separately from the encryption, the actor deployed cl.exe (the 'No-Justice' / NACL wiper, a ZEROCLEARE variant) which uses the EldoS rwdsk.sys driver to obtain raw disk access and destroy data, rendering victim systems unusable. |
| Disk Wipe: Disk Content Wipe | [T1561.001](https://attack.mitre.org/techniques/T1561/001/) | cl.exe is part of a disk-wiper utility that provides raw access to the hard drive (via the EldoS RawDisk driver) for the express purpose of overwriting/wiping data content on the physical disk. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | As a ZEROCLEARE-lineage wiper, the No-Justice tooling corrupts disk structures (boot sector / partition data) through raw disk access to prevent the system from booting, in addition to destroying file content. |
| Defacement: Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) | win.bat (#2) sets the desktop wallpaper on victim hosts to a Homeland Justice message image (goxml.jpg), an internal defacement delivering the actor's political messaging directly on compromised endpoints. |
| Defacement: External Defacement | [T1491.002](https://attack.mitre.org/techniques/T1491/002/) | Following the destruction, the actor publicized the intrusion and leaked stolen Albanian government data through the external Homeland Justice Telegram channel and leak website, using public messaging/defacement for psychological and political impact. |
