# Hunt: Imperial Kitten infostealer low-signal collection — keylogging, screen capture, automated harvest

- **Hypothesis:** If a Tortoiseshell infostealer (Sha.exe / Sha432.exe / stereoversioncontrol.exe or a custom .NET implant) is running, then a non-interactive, unsigned or masquerading process is holding low-level input hooks and periodically grabbing the screen while writing many small, regularly-timed capture artifacts to a working directory — behavior with almost no discrete log line of its own, only inferable from stacked API-use and file-write patterns. The evidence stacks an unexpected-relationship anomaly (a background/non-GUI process calling keyboard-hook and screen-capture APIs) with an improper-timing anomaly (fixed-interval screenshot/keystroke-flush writes) and a masquerading anomaly (a benign-looking name in a temp/user-writable path).
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (credential-access)
  - T1113 — Screen Capture (collection)
  - T1119 — Automated Collection (collection)

- **Actor procedure:** Imperial Kitten's custom infostealers and the Symantec-observed tools (Sha.exe, Sha432.exe, stereoversioncontrol.exe) automatically collect credentials, browser data, host information, keystrokes and desktop screenshots from compromised hosts, staging the output for exfiltration (often via the IMAP channel in HUNT-01). Keystroke hooking and screen-capture use OS APIs that emit little to no event-log signal, so the behavior surfaces mainly through EDR API-telemetry and the cadence/shape of the artifacts the collector writes.
- **Why a hunt, not a rule:** The enabling APIs (`SetWindowsHookEx`, `GetAsyncKeyState`, `BitBlt`/`GetDC`, GDI+ encode) are used by countless legitimate programs — remote-support tools, screen recorders, accessibility software, clipboard managers — so a rule on any one API drowns in false positives. There is no clean single event; the signal is the *correlation* of hooking + periodic capture + small timed writes by an unusual process, which needs baselining and judgement → hunt. A narrow, durable combination (a non-allowlisted background process holding a keyboard hook *and* issuing periodic screen captures — Summiting Level 4 behavior) is a candidate to hand to detection-engineering once the legitimate-tool allowlist is built.

## Data sources required

- EDR API/behavioral telemetry — keyboard-hook installation (`SetWindowsHookEx WH_KEYBOARD_LL`), `GetAsyncKeyState` polling, screen-capture APIs (`BitBlt`, `GetDC`, `PrintWindow`, DXGI desktop duplication)
- Sysmon EID 1 (process create) — Image, ParentImage, signing status, integrity level, session/interactivity
- Sysmon EID 11 (file create) — small periodic writes of image (.bmp/.png/.jpg/.dat) or keystroke-log files to temp/user-writable paths
- Named-tool telemetry — execution of `sha.exe`, `sha432.exe`, `stereoversioncontrol.exe`, `bak.exe`

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — background process writing periodic capture artifacts, stacked with named-tool check

```kusto
// (a) periodic small image/keystroke writes by a non-mainstream, unsigned process
let capExt = dynamic([".bmp",".png",".jpg",".jpeg",".dat",".log",".klg"]);
DeviceFileEvents
| where TimeGenerated > ago(14d)
| where FolderPath has_any (@"\Windows\Temp", @"\AppData\Local\Temp", @"\Users\Public")
| extend ext = tolower(tostring(extract(@"(\.[a-z0-9]+)$", 1, FileName)))
| where ext in (capExt)
| summarize writes = count(), span = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated)),
            files = dcount(FileName)
        by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where writes >= 20 and files >= 20 and span >= 30       // many small timed artifacts = automated capture
| order by writes desc
// Pivot: join InitiatingProcessFileName to DeviceProcessEvents for signing/parent; unsigned + odd parent = strong
// (b) named Tortoiseshell collectors — direct pivot
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName in~ ("sha.exe","sha432.exe","stereoversioncontrol.exe","bak.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
```

Platform: `SPL / Splunk` — keyboard-hook + screen-capture API use by the same unusual process

```spl
index=edr sourcetype=edr:api (api="SetWindowsHookEx" OR api="GetAsyncKeyState"
    OR api="BitBlt" OR api="PrintWindow" OR api="GetDC")
| stats values(api) as apis dc(api) as api_kinds count by host,process_name,process_path,signature_verified
| where api_kinds>=2 AND (match(apis,"SetWindowsHookEx|GetAsyncKeyState") AND match(apis,"BitBlt|PrintWindow|GetDC"))
| where signature_verified!="Signed" OR process_path="*\\Temp\\*" OR process_path="*\\Public\\*"
| sort - count
```

## Triage guidance

- **Likely malicious:** an unsigned or oddly-named background (non-GUI, non-interactive) process that both installs a low-level keyboard hook and periodically captures the screen, writing many small timed artifacts to `\Windows\Temp` or a user-writable path; any execution of `sha.exe`/`sha432.exe`/`stereoversioncontrol.exe`/`bak.exe`; the capture directory later read by an archiver or the IMAP-C2 process (HUNT-01).
- **Likely benign / expected:** screen recorders (OBS, Teams/Zoom capture), remote-support agents, accessibility/AT software, DLP screen-logging, clipboard managers, and password managers legitimately hook input and capture the screen — allowlist their signed binaries and known install paths; user-initiated interactive recording is expected. A single signed known tool is not this actor.
- **Pivot next:** pull the process binary for triage and confirm signing/lineage; enumerate the capture/working directory and check for staged archives (HUNT-07) and an outbound IMAP/web exfil path (HUNT-01/02); scope the same binary hash across the fleet. Confirmed active keylogger/screen-grabber on a corporate host is credential-theft in progress → escalate to IR and prioritize password resets for the affected user.

## References

- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://www.security.com/threat-intelligence/tortoiseshell-apt-supply-chain
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1119/
