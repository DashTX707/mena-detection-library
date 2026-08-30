# Hunt: APT39 / Chafer surveillance collection suite (keylog + screen + clipboard + input capture)

- **Hypothesis:** If APT39 has planted its personal-surveillance toolkit on a targeted user's host, then — because the actor's mission is monitoring specific individuals rather than smash-and-grab — a long-lived, low-privilege process should be *simultaneously* hooking keyboard input, periodically capturing the screen, and reading the clipboard, then writing the harvest to a growing set of local files (`.log`, `.dat`, `.jpg`/`.bmp`, timestamped names) in a user-writable/temp path. The discriminating signal is the *co-occurrence of multiple capture modalities in one process lineage* plus a slow, steady on-disk growth pattern — not any single API call, which is individually near-invisible.
- **ATT&CK:**
  - T1056 — Input Capture (collection) — parent capture behavior
  - T1056.001 — Input Capture: Keylogging (credential-access) — keystroke hooking
  - T1113 — Screen Capture (collection) — periodic desktop screenshots
  - T1115 — Clipboard Data (collection) — clipboard harvesting

- **Actor procedure:** APT39/Chafer deploys custom keyloggers and custom screenshot tools (and the Remexi/Cadelspy backdoor families) whose purpose is to surveil persons of interest — telecom/travel-sector staff and dissidents — capturing what the target types, sees, and copies. The harvest is staged locally, often lightly encoded, and later pulled back over the actor's C2 (see HUNT-04). The capture modules run persistently and quietly for weeks so the operator can track the individual over time.
- **Why a hunt, not a rule:** The core capture APIs — `SetWindowsHookEx`/`GetAsyncKeyState` (keylog), `BitBlt`/`GetDC` (screen), `OpenClipboard`/`GetClipboardData` (clipboard) — are used by legions of legitimate apps (IMEs, remote-support tools, screenshot utilities, password managers, accessibility software), so any single one alerts into a swamp of false positives. The threat signal is *relational and cumulative*: one modest, non-Store, unsigned/oddly-signed process doing two-or-three of these at once, persisting across logons, and leaving a slowly growing capture file. That stacking + baselining is judgement-heavy → hunt. If the hunt yields a stable allowlist of legitimate multi-modal capturers, the residual "unsigned process hooking keyboard AND writing periodic screenshots" (Summiting Level 4, implementation-core) can be handed to detection-engineering.

## Data sources required

- Sysmon EID 1 (process create, full lineage) + EID 7 (image/DLL load — `user32`/`gdi32` hook context) on user endpoints
- EDR behavioral telemetry: keyboard-hook installation (`SetWindowsHookEx WH_KEYBOARD_LL`), screen-capture (`BitBlt`/`GetDC`/`PrintWindow`), clipboard-read API tagging
- Sysmon EID 11 (file create) — periodic same-process writes to `.log`/`.dat`/`.jpg`/`.bmp` in `%TEMP%`, `%APPDATA%`, `%PUBLIC%`
- Autoruns/persistence context (Run keys, scheduled tasks) to confirm the capturer survives logon

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — one process stacking multiple capture modalities + steady file growth

```kusto
// Processes exhibiting >=2 capture modalities (keylog / screen / clipboard) in a 24h window
let capture = DeviceEvents
| where TimeGenerated > ago(14d)
| extend api = tostring(parse_json(AdditionalFields).ApiName)
| extend modality = case(
    ActionType has_any ("KeyboardHook","LowLevelHook") or api has_any ("SetWindowsHookEx","GetAsyncKeyState"), "keylog",
    ActionType has "ScreenCapture" or api has_any ("BitBlt","GetDC","PrintWindow"), "screen",
    ActionType has "Clipboard" or api has_any ("GetClipboardData","OpenClipboard"), "clipboard",
    "");
capture
| where modality != ""
| summarize modalities = make_set(modality), n = dcount(modality),
            first = min(TimeGenerated), last = max(TimeGenerated)
        by DeviceName, InitiatingProcessSHA1, InitiatingProcessFolderPath, InitiatingProcessFileName
| where n >= 2                                  // multi-modal capture in one process
| join kind=leftouter (
    DeviceFileEvents
    | where TimeGenerated > ago(14d)
    | where FileName matches regex @"(?i)\.(log|dat|jpg|bmp|png)$"
    | where FolderPath has_any (@"\Temp\", @"\AppData\", @"\Public\")
    | summarize capFiles = dcount(FileName), bytes = sum(tolong(FileSize))
            by DeviceName, InitiatingProcessSHA1
) on DeviceName, $left.InitiatingProcessSHA1 == $right.InitiatingProcessSHA1
| where isnotempty(capFiles)                    // capture that persists to disk
| order by n desc, bytes desc
// Exclude allowlisted remote-support / IME / screenshot tooling by signer+path (wiki baseline)
```

## Triage guidance

- **Likely malicious:** a single unsigned or oddly-signed process (non-Microsoft, non-Store, running from `%TEMP%`/`%APPDATA%`) that hooks the keyboard AND periodically captures the screen AND/OR reads the clipboard, persisting across logons via a Run key or scheduled task, and steadily growing a `.log`/`.dat`/image cache — this is textbook APT39 individual-surveillance tooling. Elevated concern if the target user is telecom/travel/HR/legal staff or a person-of-interest.
- **Likely benign / expected:** remote-support agents (TeamViewer, AnyDesk, ScreenConnect), password managers and clipboard managers, IMEs/accessibility tools, corporate screenshot/DLP agents, and QA/automation tools legitimately do one or more of these — allowlist by signer + install path + known behavior. A signed vendor agent doing screen capture on a support session is expected; an unknown binary doing all three quietly is not.
- **Pivot next:** confirm persistence mechanism and first-seen time (scope the dwell); pull the capture files and check for encoding/encryption (cross-ref T1027.013/T1140 detection pack); trace the process's outbound sessions to the C2/exfil path (HUNT-04, HUNT-02); identify the surveilled user and notify. A confirmed live keylogger on a targeted individual is an active espionage incident → escalate to IR.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1115/
- https://www.mandiant.com/resources/blog/apt39-iranian-cyber-espionage-group-focused-on-personal-information
