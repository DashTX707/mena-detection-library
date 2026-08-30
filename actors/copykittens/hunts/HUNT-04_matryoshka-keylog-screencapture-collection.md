# Hunt: CopyKittens — Matryoshka keylogging, screen-capture and local-file collection

- **Hypothesis:** If Matryoshka is collecting on a host, then espionage collection — keylogging, periodic screenshots, and pulling files of interest / stored passwords from the local system — leaves almost no discrete host event on its own, but it produces a *behavioral cluster around one implant process*: keyboard-hook / raw-input API usage or a growing keystroke-log file, periodic GDI/DirectX screen-grab API calls or a cadence of image-like blobs written to a working directory, and bursty read access across document/credential locations by a process that is neither an Office app nor a backup agent — all attributable to the same rundll32-hosted DLL or injected process that (per HUNT-01) also talks DNS C2. The finding is that collection cluster tied to a single non-interactive implant, not any one API call; a screenshot API call by a conferencing app or a keyboard hook by an IME is benign in isolation, but the same process doing hook + screen-grab + broad local-file reads + DNS beacon is Matryoshka collection.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (credential-access) — Matryoshka records keystrokes to steal typed credentials; hunted via keyboard-hook/raw-input API telemetry and keystroke-log file growth correlated to the implant.
  - T1113 — Screen Capture (collection) — Matryoshka periodically screenshots the desktop; hunted via screen-grab API cadence and image-blob writes by a non-interactive process.
  - T1005 — Data from Local System (collection) — Matryoshka collects files of interest and stored passwords; hunted via bursty cross-directory read access by the implant process, distinct from backup/index agents.

- **Actor procedure:** Matryoshka RAT (v1/v2) is an espionage implant: it logs keystrokes (T1056.001) to capture credentials and sensitive typed content, captures screenshots of the victim desktop (T1113), and collects files of interest and stored passwords from the local system (T1005). Collected artifacts are staged (HUNT-05) and exfiltrated back through the DNS channel (HUNT-01, detection pack T1041/T1048.003). The collection components run inside rundll32-hosted DLLs or an injected process (detection pack T1218.011/T1055), typically with a hidden window (detection pack T1564.003), so the activity is invisible to the interactive user and only surfaces as a behavioral cluster on one process.
- **Why a hunt, not a rule:** Keylogging, screen capture and local-file reads are individually near-invisible and heavily dual-use — SetWindowsHookEx is used by IMEs, accessibility tools, macro utilities and legitimate keyboard software; screen-capture APIs by conferencing, screen-recording and remote-support tools; broad local-file reads by backup, search-indexer and DLP agents. A rule on any one drowns in benign use. The signal is the *convergence* on a single non-interactive, unsigned/anomalous process that also carries C2 lineage — a correlation across API, file-write and network telemetry that needs baselining of legitimate hook/capture/read agents and analyst judgement. If a durable, specific tuple emerges (e.g., "process with a keyboard hook AND periodic screen-grab AND outbound DNS to a flagged apex"), hand that behavioral composite to detection-engineering as a scoped analytic — the individual APIs are too noisy to alert on alone.

## Data sources required

- EDR API/behavioral telemetry: keyboard-hook (SetWindowsHookEx WH_KEYBOARD_LL), GetAsyncKeyState/RawInput, screen-grab (BitBlt/GetDC/PrintWindow/Desktop Duplication) attributed per process
- File-write telemetry for keystroke-log and screenshot artifacts (small, periodic writes to temp/working dirs); file-read/access auditing (EID 4663) for cross-directory document/credential reads
- Process lineage (Sysmon EID 1/7/8/10) linking the collector to rundll32/DLL loader, injection, and hidden-window flags
- Baseline inventory of sanctioned hook/screen-capture/backup/indexer/DLP agents for suppression

## Query starting point

Platform: `EDR via KQL` — converge keylog + screen-capture + local-file reads on one non-interactive process

```kusto
let window = 14d;
let interesting_paths = dynamic(["\\Documents\\","\\Desktop\\","\\Downloads\\","\\AppData\\Roaming\\","password","credential",".kdbx",".pst"]);
// (a) processes exercising input-capture / screen-grab behaviors
let capture = DeviceEvents
    | where Timestamp > ago(window)
    | where ActionType in ("SetWindowsHookExApiCall","GetAsyncKeyStateApiCall","ScreenCaptureApiCall","BitBltApiCall")
    | summarize behaviors=make_set(ActionType), capture_hits=count() by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath;
// (b) same process reading broadly across document/credential locations
let reads = DeviceFileEvents
    | where Timestamp > ago(window) and ActionType == "FileAccessed"
    | where FolderPath has_any (interesting_paths) or FileName has_any (interesting_paths)
    | summarize dirs=dcount(FolderPath), files=dcount(FileName) by DeviceName, InitiatingProcessId, InitiatingProcessFileName;
capture
| join kind=inner (reads) on DeviceName, InitiatingProcessId
| where array_length(behaviors) >= 2 and dirs >= 5           // hook/grab cluster + broad reads
| where InitiatingProcessFileName !in~ ("teams.exe","zoom.exe","onedrive.exe","searchindexer.exe")  // baseline suppress
| extend suspicious_host = InitiatingProcessFileName =~ "rundll32.exe" or InitiatingProcessFolderPath has_any ("\\Temp\\","\\AppData\\")
| project DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, behaviors, capture_hits, dirs, files, suspicious_host
| order by suspicious_host desc, capture_hits desc
```
Corroborate survivors against the process's network lineage (does it also beacon DNS to a HUNT-01 apex?) and against a hidden-window flag / injected-thread origin.

## Triage guidance

- **Likely malicious:** a single non-interactive process — especially `rundll32.exe` hosting a DLL from a temp/user path, or an injected thread in a legitimate process — that combines a keyboard hook, periodic screen-grab API calls, and broad read access across Documents/Desktop/credential stores, and is the same process talking DNS C2 (HUNT-01). Small periodic image/log-file writes to a working directory alongside this cluster indicate active keylog + screenshot staging.
- **Likely benign / expected:** IMEs, accessibility software, password managers, macro/hotkey utilities legitimately install keyboard hooks; conferencing, screen-recording and remote-support tools call screen-capture APIs continuously; backup, search-indexer and DLP agents read broadly across user directories — baseline and suppress these signed, known agents. A hook without screen-grab, or screen-grab without broad reads, on a signed interactive app is expected; the full cluster on an unsigned non-interactive process is not.
- **Pivot next:** confirm the collector's persistence (detection pack T1547.001/T1053.005), its C2/exfil path (HUNT-01, detection pack T1041), and its staging/archiving (HUNT-05). Pull the implant to confirm the keylog/screenshot routines and the decode logic (HUNT-01 T1140). A confirmed active espionage implant collecting from a user desktop is a live compromise — escalate to incident-response-coordinator and hand the behavioral composite (hook + screen-grab + broad-read + DNS-beacon on one process) to detection-engineering.

## References

- https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1005/
