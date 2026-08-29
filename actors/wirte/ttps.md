# WIRTE (G0090) — ATT&CK Technique Mapping

> Attribution: Palestinian-nexus (assessed Hamas-affiliated) — medium confidence. MITRE ID: G0090.
> Enriched from MITRE ATT&CK G0090 + Securelist & Check Point reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **39** across **11** tactics. Spans LotL espionage + the SameCoin destructive turn (Impact).

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | WIRTE registers themed domains following a consistent naming convention (health, finance, and regional-country themes, e.g. saudiday[.]org, jordansons[.]com, egyptican[.]com, king-pharmacy[.]com, master-dental[.]com) used as C2 and phishing infrastructure, frequently fronted by Cloudflare to hide the real VPS IP. |
| Compromise Accounts: Email Accounts | [T1586.002](https://attack.mitre.org/techniques/T1586/002/) | In the October 2024 SameCoin wave, WIRTE sent the wiper-laden phishing email from the legitimate, compromised mailbox of an Israeli ESET reseller, lending credibility to the lure targeting Israeli hospitals and municipalities. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | WIRTE obtained and operationalized the open-source Havoc post-exploitation framework (Havoc Demon agent) as a delivered payload in the September 2024 campaign, alongside donut shellcode loading. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | WIRTE stages malicious payloads on its own domains/servers — RAR/ZIP archives, lure PDFs, and next-stage payloads embedded within HTML tags on C2 servers — served only to requests bearing the expected hardcoded user agent (otherwise redirected to a legitimate news/health site). |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | WIRTE develops custom malware in-house: the Ferocious dropper, LitePower PowerShell stager, the IronWind loader, and the SameCoin wiper. A unique XOR encryption routine shared between the IronWind loader (propsys.dll) and the SameCoin wiper component (MicrosoftEdge.exe) indicates the same developer and likely the same build environment. |

## Stealth

| Technique | ID | Notes |
|---|---|---|
| Improper Impersonation: Impersonation | [T1684.001](https://attack.mitre.org/techniques/T1684/001/) | WIRTE impersonates trusted institutions and brands to increase lure credibility: SameCoin posed as an Israeli National Cyber Directorate (INCD) security update (Feb 2024) and as an ESET security notice (Oct 2024); espionage lures mimicked the Palestinian Authority and used official-looking Arabic government/diplomatic themes. |
| System Binary Proxy Execution: Regsvr32 | [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | In the earliest (Lab52-documented) WIRTE activity, the actor used regsvr32.exe as a living-off-the-land technique to proxy execution and evade defenses; later intrusions shifted to COM hijacking as the LotL mechanism. |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | WIRTE names payloads to impersonate legitimate software and system components: a fake 'Kaspersky Update Agent.exe' dropper, wiper/infector components named MicrosoftEdge.exe, csrs.exe, 'Microsoft System Manager.exe', 'Windows Defender Agent.exe', and 'Microsoft Connection Agent.jpg', plus legitimate EXEs renamed to Arabic lure titles to host DLL sideloading. |
| Obfuscated Files or Information: Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | WIRTE obfuscates payloads and strings throughout the chain: Excel-4.0 formulas hidden in secondary spreadsheets/columns, XOR-encrypted strings (keys such as '01-01-1900' and 'Saturday, October 07, 2023, 6:29:00 AM'), Base64+XOR-encoded second stages (IronWind key '53'), and payloads embedded between HTML tags served only to a specific user agent. |
| Obfuscated Files or Information: Compression | [T1027.015](https://attack.mitre.org/techniques/T1027/015/) | WIRTE packages the multi-file infection sets inside RAR and ZIP archives (e.g. the Arabic-titled RAR archives containing a renamed EXE + lure PDF + malicious DLL, and ESETUnleashed_081024.zip containing legit DLLs + Setup.exe) to bundle payloads and hinder inspection during delivery. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | The chain decodes/decrypts staged content at runtime: IronWind Base64-decodes then XOR-decrypts the propsys.dll second stage (key '53'); the SameCoin Oct-2024 loader derives its XOR key from the first bytes of the oref.org.il HTTP response and decrypts the dropped wiper/infector/wallpaper/video files; propsys.dll decodes IP-string-encoded payload bytes. |
| Virtualization/Sandbox Evasion: System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | The Ferocious Excel dropper runs three anti-sandbox checks via the Excel-4.0 GET.WORKSPACE function: environment name/version (compared against predefined Windows version strings to bail on analysis VMs), presence of a mouse (arg 19), and sound-playback capability (arg 42). If any check fails or the OS version matches a blocklisted value, execution halts. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | WIRTE sends spear-phishing emails with malicious attachments: Excel documents with hidden Excel-4.0 (XLM) macro spreadsheets and Word documents with VBA macros (espionage), and ZIP archives containing a malicious Setup.exe alongside legitimate DLLs (the Oct 2024 SameCoin wave). |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | WIRTE delivers links to malicious payloads and phishing pages: lure PDFs embed a URL-shortener-style link (theshortner[.]com) redirecting to a RAR archive, and WIRTE hosts Docdroid-mimicking phishing pages (suppertools[.]com, healthscratches[.]com) that serve content or a document conditionally on visitor IP. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Infection requires the victim to open the malicious document and click 'enable editing'/'enable content' to run the Excel-4.0 or VBA macro, or to extract and run the renamed legitimate EXE (DLL-sideload host) / Setup.exe from the delivered archive. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | WIRTE relies on the victim clicking an embedded link in a lure PDF or email (e.g. the theshortner[.]com shortener) to fetch the malicious archive or reach a phishing page. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | The Ferocious dropper writes and executes VBScript stagers (winrm.vbs) via explorer.exe; the malicious VBS is also the target of COM-hijacking persistence. Word droppers use VBA macros to download the payload. XOR-encrypted strings (key such as '01-01-1900') are used within the sideloaded stages. |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | The LitePower stager is a PowerShell downloader that beacons to C2, parses returned PowerShell functions, and executes them via IEX; it runs WMI-based recon (disk, AV, OS architecture, admin check) and screenshot functions. Ferocious writes an embedded PowerShell snippet and a PowerShell one-liner stager wrapped in VB. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | The IronWind/Havoc chains save the lure document as a PDF and open it via cmd.exe (CMD) to appear benign to the user while the sideloaded DLL executes in the background. |
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | The propsys.dll loader reconstructs its next-stage payload by iterating a long embedded list of IP-formatted strings and calling the RtlIpv4StringToAddressA API to convert each string into bytes, concatenating them into the payload — using a native Windows API for payload decoding/assembly. |
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | LitePower creates a legitimate-looking scheduled task that triggers 'Scripting.Dictionary' COM programs (via slmgr.vbs/winrm.vbs), which is the trigger that activates the COM-hijacking persistence. In the SameCoin operation, the csrs.exe InfectAD function and the earlier 'Tasks Spreader' component copy the wiper to remote/AD machines and schedule its execution using remote scheduled tasks. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Event Triggered Execution: Component Object Model Hijacking | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | WIRTE's signature persistence: the Ferocious VBS stager adds a Class ID under HKCU\Software\Classes\CLSID\{...}\LocalServer32 that references the malicious winrm.vbs, hijacking the 'Scripting.Dictionary' COM object so the VBS is invoked whenever a program/script (e.g. the legitimate winrm.vbs/slmgr.vbs) references that COM programmatic ID. Observed CLSIDs include {50236F14-2C02-4291-93AB-B5A80F9666B0} and {14C34482-E07F-44CF-B261-385B616C54EC}. |
| Hijack Execution Flow: DLL Search Order Hijacking | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | The IronWind and Havoc infection chains use DLL side-loading: a legitimate, digitally trusted executable (renamed to an Arabic lure name, e.g. setup_wm.exe or PinEnrollmentBroker.exe) is shipped alongside a malicious DLL (version.dll / propsys.dll) that is loaded in place of the expected system library when the trusted EXE runs. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| System Location Discovery: System Language Discovery | [T1614.001](https://attack.mitre.org/techniques/T1614/001/) | The SameCoin wiper geofences its destruction to Israel: the Windows variant checks whether the system language is set to Hebrew before dropping and detonating its wiper/propaganda payload, and the Oct-2024 variant additionally verifies the target is inside Israel by requiring a successful response from the Israel-only Home Front Command site oref.org.il (also using that response as its XOR key). |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | IronWind profiles the victim on first contact, sending Office version, OS version, computer name, username, and the list of installed programs to requestinspector.com. LitePower separately queries OS caption/architecture and local disk volume serial number via WMI. |
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | LitePower queries installed antivirus via the WMI 'SELECT * FROM AntiVirusProduct' query against root\SecurityCenter2, returning the product display name (or 'N/A'), to assess defenses before follow-on activity. |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | LitePower checks whether the current user holds Administrator privileges (WindowsPrincipal IsInRole Administrator) and reports the username; IronWind includes the username in its initial victim-profiling beacon. |
| Permission Groups Discovery: Domain Groups | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | LitePower's Get-ServiceStatus function checks whether the host is part of a domain and whether the current user is a member of 'Domain Admins', informing lateral-movement and escalation decisions. |

## Command And Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | WIRTE C2 rides HTTP/HTTPS: LitePower sends command results via HTTP POST and fetches PowerShell commands via HTTP GET, using a unique hardcoded User-Agent (Mozilla/5.0 ... rv:FTS_06 ...) whose 'rv' field is varied per intrusion for tracking. IronWind/Havoc beacon over HTTP, retrieving next-stage payloads embedded within HTML tags and responding only to the expected user agent (otherwise redirecting to a legitimate site). |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Older WIRTE intrusions used non-standard C2 ports — TLS listeners observed on TCP 2083, 2087, 8443 (and, per Lab52, 2096/2087) with per-port certificate common names (firstohiobank[.]com on 2083/8443, dentalmatrix[.]net on 2087) — while newer intrusions consolidated onto TCP/443. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | LitePower downloads and deploys further payloads/commands from its C2, and the IronWind/Havoc loaders pull next-stage payloads (embedded in HTML tags, or Havoc Demon) down onto the victim for execution. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | LitePower includes a Screenshot function that captures the victim's screen, saves the image to %AppData%, and exfiltrates it to the C2 via an HTTP POST request. |
| Email Collection: Local Email Collection | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | The SameCoin infector component csrs.exe implements InfectOutlook, which reads other recipient addresses within the same organization from Outlook in order to re-send the malicious Setup.exe to them, harvesting local mailbox contacts to fuel internal spread. |
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | WIRTE stages collected data and working artifacts locally before exfiltration/execution, using %ProgramData% as a consistent working directory (winrm.vbs/winrm.txt/regionh.txt) and saving captured screenshots to %AppData% prior to POSTing them to the C2. |

## Lateral Movement

| Technique | ID | Notes |
|---|---|---|
| Internal Spearphishing | [T1534](https://attack.mitre.org/techniques/T1534/) | The SameCoin InfectOutlook function (csrs.exe) spreads by sending the malicious Setup.exe as an attachment from the compromised host to other addresses within the same organization, abusing trusted internal mail relationships to move laterally and widen the wiper's blast radius. |
| Lateral Tool Transfer | [T1570](https://attack.mitre.org/techniques/T1570/) | The SameCoin InfectAD function (csrs.exe) and the Feb-2024 'Tasks Spreader' component copy the wiper/loader to other machines within the same Active Directory environment and schedule remote execution, propagating the destructive payload across the network. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | WIRTE exfiltrates over its existing C2 channel: LitePower returns command output and captured screenshots to the C2 via HTTP POST, and IronWind POSTs the initial host-profile inventory to its collection endpoint. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | WIRTE's destructive turn: the SameCoin wiper enumerates all files outside protected directories (Program Files, Windows, Users) and, unless a filename contains 'desktop.ini' or 'conf.conf', overwrites each file with random bytes, rendering data irrecoverable. The Android variant (libexampleone.so) lists targeted files, fills them with zeros, then deletes them from the filesystem. |
| Defacement: Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) | As part of the SameCoin destructive payload, WIRTE changes the victim's desktop wallpaper to an image referencing Hamas's military wing, the Al-Qassam Brigades (dropped as image.jpg / 'Microsoft Connection Agent.jpg'), and drops/plays a Hamas propaganda video (video.mp4) showing footage from the October 7 attacks — an overt political defacement accompanying the wipe. |
