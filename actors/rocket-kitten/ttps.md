# Rocket Kitten — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium-high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **34** across **11** tactics.

## Reconnaissance

| Technique | ID | Notes |
|---|---|---|
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | Actors research individual targets (names, roles, email addresses, phone numbers, professional interests) to craft highly tailored spear-phishing lures and fake identities; the recovered operational database held ~1,600 profiled targets. |
| Gather Victim Org Information | [T1591](https://attack.mitre.org/techniques/T1591/) | Actors identify and prioritize target organizations of Iranian state interest — Israeli defense and academic institutions, ministries, research institutes, media outlets and human-rights NGOs — to focus espionage collection. |
| Phishing for Information: Spearphishing Link | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Actors operate fake-login / credential-harvesting web pages (spoofing webmail and institutional portal logins) linked from spear-phishing messages to capture target account credentials; a dedicated phishing server supported this. |

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Establish Accounts: Social Media Accounts | [T1585.001](https://attack.mitre.org/techniques/T1585/001/) | Actors create fake social-media personas (e.g. Facebook profiles communicating in perfect Farsi/Hebrew) to build rapport with targets; when a profile is taken down they recreate it (e.g. 'mah.asf.xxx' where xxx is a random number). One fake profile even sent a friend request to a ClearSky researcher. |
| Establish Accounts: Email Accounts | [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | Actors register webmail persona accounts to correspond with targets and send lures (e.g. a Yahoo account '[name]_asf@yahoo.com', and a Gmail sender clearsky.cybersec.group@gmail.com impersonating the ClearSky research group). |
| Compromise Accounts: Email Accounts | [T1586.002](https://attack.mitre.org/techniques/T1586/002/) | Actors impersonate real, recognizable people (a known Israeli engineer, a defense-field figure) and are assessed to have compromised at least one such person's computer to steal genuine documents (identical file metadata) subsequently reused as authentic-looking lures against other Israeli targets. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Actors register phishing/look-alike domains and operate a phishing server for credential-harvesting fake-login pages; the group made only minimal changes to these domains even after public exposure. |
| Acquire Infrastructure: Web Services | [T1583.006](https://attack.mitre.org/techniques/T1583/006/) | Actors abuse legitimate cloud/web services — notably Microsoft OneDrive to host malicious payloads — to bypass email attachment scanning, and used the free Iranian multiscanner av.zerodays.ir to pre-test their samples' detection. |
| Stage Capabilities: Upload Malware | [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | Actors upload malicious executables to cloud storage for delivery — e.g. an archive containing 'Iran's Missiles Program.ppt.exe' (PowerPoint icon, double extension) staged on a OneDrive link sent to targets. |
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Actors developed the custom CWoolger keylogger (TSPY_WOOLERG); leaked PDB debug paths (C:\Users\Wool3n.H4t\...\CWoolger\Release\CWoolger.pdb and D:\Yaser Logers\...) tie authorship to the operator handles Wool3n.H4t and Yaser. |
| Obtain Capabilities: Tool | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) | Actors obtain and repurpose commercial/off-the-shelf tooling — the GHOLE backdoor is a modified Core Impact Pro pentest agent. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Primary initial-access vector: tailored spear-phishing emails carrying malicious Microsoft Office attachments (Excel spreadsheets, PowerPoint, or PDF decoys) themed to the target's professional interests; opening the file and enabling macros drops the GHOLE backdoor. |
| Phishing: Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Actors send links (including OneDrive links) that lead to a malicious executable disguised with a PowerPoint icon ('Iran's Missiles Program.ppt.exe'), and links to fake-login credential-harvesting pages, storing payloads online to bypass email attachment detection. |
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Actors initiate contact and deliver lures via non-email services — fake Facebook profiles and social-media messaging — building trust in Farsi/Hebrew before delivering malicious files or links. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Compromise requires the user to open the Office attachment and enable the embedded macro (which drops/executes the GHOLE DLL), or to run the disguised '.ppt.exe' which drops a benign decoy while silently installing the CWoolger keylogger. |
| User Execution: Malicious Link | [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | Targets are induced to click OneDrive/phishing links; in one analyzed case attackers replied in Hebrew to confirm an email's authenticity, convincing the target to proceed. |
| Office Application Startup: Office Template Macros | [T1137.001](https://attack.mitre.org/techniques/T1137/001/) | Malicious Office documents embed VBA macros that, when enabled, drop the GHOLE backdoor DLL to disk and execute it; the delivery documents are detected as X2KM_DROPPR. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Delivery uses VBA macros in Office files, and the CWoolger keylogger drops a VBScript 'wsc.vbs' in %TEMP% that installs its persistence mechanism. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | The CWoolger keylogger copies itself to %TEMP%\NTSuser.exe, creates a 'woolger' mutex, and its wsc.vbs installs a Startup-folder shortcut named 'WinDefender' (using the Notepad icon) that launches the malware at logon. |
| Boot or Logon Autostart Execution: Shortcut Modification | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Persistence is implemented as a .lnk shortcut ('WinDefender', spoofing the Notepad icon) placed in the Startup folder that resolves to the keylogger binary in %TEMP%. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Masquerade File Type | [T1036.008](https://attack.mitre.org/techniques/T1036/008/) | The delivery executable uses a double extension and spoofed icon ('Iran's Missiles Program.ppt.exe' with a PowerPoint icon) to appear as a document, and the GHOLE DLL exports a benign-looking function named 'function' instead of the telltale 'gholee' to evade detection. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Malware and its artifacts adopt legitimate-looking names to blend in: keylogger drops as NTUSER.dat{GUID}.exe and %TEMP%\NTSuser.exe, persists as 'WinDefender', logs to AdobeARM.log/AdobeARMM.log, and one installer masquerades as Trend Micro HouseCall (HousecallLauncher.exe). |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Later CWoolger variants add a basic encryption layer to hide the hard-coded FTP credentials (earlier versions stored them in clear text); GHOLE carries a 256-byte (2,048-bit) key used to obfuscate network communications. |

## Impair Defenses

| Technique | ID | Notes |
|---|---|---|
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Some Rocket Kitten malware places its payload in memory and erases traces of the malware from the file system after execution to hinder forensic recovery. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | CWoolger enables keylogging via the SetWindowsHookExW API and records all keystrokes to %TEMP%\wlg.dat (later variants %TEMP%\AdobeARM.log / %TEMP%\AdobeARMM.log) in a '[Window Title] - [Application Name] ([Language])' + context format, using SetTimer to schedule uploads. |
| Input Capture: Web Portal Capture | [T1056.003](https://attack.mitre.org/techniques/T1056/003/) | Fake login pages mimicking legitimate webmail/portal sign-in forms capture the credentials entered by targets, feeding the group's account-compromise objectives. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Captured keystroke data is staged locally in %TEMP% (wlg.dat / AdobeARM.log / AdobeARMM.log) and, once a log exceeds ~3,000 bytes, queued for upload; log files are renamed LOG_(UserName)_[timestamp] prior to exfiltration. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Beyond keystrokes, actors steal documents from compromised systems — e.g. genuine files harvested from an impersonated engineer's computer were reused as lures — supporting espionage collection on victim endpoints. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | GHOLE beacons over HTTP to a hard-coded C2 IP using GET requests of the form /index.php?c=<8-byte id>&r=<5-7 byte>&u=1&t=<time>, with variants /index.php?c=%s&r=%lx and /index.php?c=%s&r=%x usable as network IOCs. |
| Encrypted Channel: Symmetric Cryptography | [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | GHOLE uses a hard-coded 256-byte (2,048-bit) symmetric key to encrypt its command-and-control network communications. |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Actors retrieve secondary payloads/decoys from attacker-controlled cloud (OneDrive) after initial link click; some keylogger versions removed the built-in uploader in favor of a separately delivered companion binary (wsnd.exe) placed in the same folder. |
| Remote Access Tools | [T1219](https://attack.mitre.org/techniques/T1219/) | GHOLE is a modified Core Impact Pro agent providing remote control/backdoor access to infected hosts; a fake Trend Micro HouseCall installer establishes a further backdoor connection to C2 84.11.146.62. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | GHOLE exfiltrates collected data to its operators over its HTTP/encrypted C2 channel to hard-coded C2 IP addresses (e.g. 83.170.33.60). |
| Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | The CWoolger keylogger exfiltrates staged keystroke logs over FTP using hard-coded credentials to attacker FTP servers (107.6.172.54/woolen/, earlier 107.6.181.116), calling an uploadToCnC function once a log exceeds ~3,000 bytes. |
