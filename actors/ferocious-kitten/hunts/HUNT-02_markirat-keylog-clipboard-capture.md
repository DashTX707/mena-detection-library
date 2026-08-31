# Hunt: MarkiRAT keystroke and clipboard capture (nfo log artifact)

- **Hypothesis:** If MarkiRAT (internal names `mklg`/`mfcmklg` = "Mark KeyLogger") is capturing input on a host, then an unsigned process from a user-writable path will hold a low-level keyboard hook and repeatedly read the clipboard, and it will write a local keystroke log file named `nfo` into its working directory (typically `%PUBLIC%\AppData\Windows`) — so the co-occurrence of persistent input-hook + clipboard-read API behavior on an unsigned process together with creation/growth of a file literally named `nfo` is a masquerading + unexpected-relationship anomaly that legitimate software does not reproduce.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (collection)
  - T1115 — Clipboard Data (collection)
- **Actor procedure:** MarkiRAT records the victim's keystrokes to a local log file named `nfo` for later exfiltration and simultaneously captures Windows clipboard contents to harvest copied credentials, messages and sensitive text. It first kills the KeePass process (see HUNT-01) so the master password is re-typed and captured, then stages `nfo` alongside `scr.jpg` for upload to `/up/uploadx.php`.
- **Why a hunt, not a rule:** User-mode keystroke hooking (`SetWindowsHookEx`/`GetAsyncKeyState`) and clipboard reads (`OpenClipboard`/`GetClipboardData`) are native APIs used by countless benign apps and are not reliably logged, so a standalone rule is unworkable. The durable hunt is behavioral + artifact-based: EDR hook/clipboard sensor signal attributed to an unsigned user-path process, corroborated by a file named `nfo` appearing in a malware-style repository — requiring correlation and baselining rather than a single precise alert.

## Data sources required

- EDR API-behavior telemetry (keyboard-hook install `SetWindowsHookEx`/`WH_KEYBOARD_LL`, clipboard reads `GetClipboardData`) attributed to process image + signer
- Sysmon EID 11 (file create) and file-modify telemetry for a file named `nfo` (no extension) under `%PUBLIC%`, `%APPDATA%`, Telegram/Chrome data dirs
- Sysmon EID 1 / 4688 (process image, signer, parent) to attribute the hooking process

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint EventCode=11 (TargetFilename="C:\\Users\\Public\\*\\nfo"
    OR TargetFilename="*\\AppData\\Windows\\nfo" OR TargetFilename="*\\nfo")
| regex TargetFilename="\\\\nfo$"
| rename process_guid as pguid
| join type=left pguid [
    search index=edr (behavior="keyboard_hook" OR api="SetWindowsHookEx"
                      OR behavior="clipboard_read" OR api="GetClipboardData")
    | stats values(behavior) as capture_behaviors by pguid ]
| join type=left pguid [
    search index=endpoint (EventCode=1 OR EventCode=4688)
    | eval img=lower(coalesce(Image,New_Process_Name))
    | fields pguid img Signed ParentImage ]
| where Signed!="true" OR isnotnull(capture_behaviors)
| table _time host img Signed ParentImage TargetFilename capture_behaviors
```

## Triage guidance

- **Likely malicious:** A file named `nfo` (no extension) created/appended by an unsigned process running from `\Users\Public\`, `\AppData\Windows`, or a Telegram/Chrome data directory; that same process holding a global keyboard hook and reading the clipboard; parent chain traceable to `WINWORD.EXE`, `svehost.exe`, or a hijacked browser/messenger shortcut.
- **Likely benign / expected:** Password managers, remote-support agents, screen readers, and clipboard-manager utilities install keyboard hooks and read the clipboard — but they are signed and run from Program Files. Files coincidentally named `nfo` (e.g. `.nfo` media-info files, release-note text) differ from the extensionless `nfo`; baseline signed hooking apps per host and suppress them.
- **Pivot next:** If the implant is confirmed, pivot to HUNT-01 (KeePass kill / AV fingerprint) and HUNT-03 (file collection), and check for the screenshot artifact `scr.jpg` and outbound HTTP upload to `/up/uploadx.php`. A confirmed keylogger capturing credentials is a live compromise — **escalate to incident-response** and treat all credentials typed on the host as exposed.

## References

- https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/
- https://www.picussecurity.com/resource/blog/ferocious-kitten-apt-exposed-inside-the-iran-focused-espionage-campaign
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1115/
