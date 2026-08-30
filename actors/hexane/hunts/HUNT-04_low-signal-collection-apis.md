# Hunt: HEXANE low-signal user-surveillance collection (keylogging, screen capture, window enumeration)

- **Hypothesis:** If a HEXANE implant (Milan / the PowerShell-DNS keylogger) is surveilling a user on one of our hosts, then even though the capture APIs themselves emit almost no discrete log, the surrounding behavior should betray it — a non-interactive/unsigned process that stacks the surveillance primitives together: enumerating foreground application windows (to know what to capture), setting a low-level keyboard hook, and periodically grabbing the screen, then writing small artifacts to a working directory and beaconing them out. The finding is one process exhibiting *several* of these primitives, not any single common API call.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (collection)
  - T1113 — Screen Capture (collection)
  - T1010 — Application Window Discovery (collection/discovery)

- **Actor procedure:** HEXANE deployed a keylogger (a PowerShell/DNS keylogger and Milan implant components) to capture keystrokes, captured screenshots from compromised hosts, and enumerated open application windows — classic espionage user-surveillance to harvest credentials and monitor targeted IT/comms staff, with capture output funneled into its DNS/HTTP C2.
- **Why a hunt, not a rule:** The core APIs — `SetWindowsHookEx`, `GetForegroundWindow`/`EnumWindows`, `BitBlt`/`GetDC` — are used pervasively by legitimate software (IMEs, accessibility tools, screen-sharing, remote-support, clipboard managers, games), so a rule on any one of them drowns in false positives. There is no precise low-FP selector; detection requires behavioural EDR sensor coverage plus an analyst correlating the primitives *and* the process's provenance (unsigned, odd parent, beaconing). That correlation and baselining is judgement-heavy → hunt. If EDR reliably ties a keyboard-hook + screen-grab + beacon to an unsigned process, that stacked behaviour is a candidate to hand to detection-engineering.

## Data sources required

- EDR API/behavioural telemetry — `SetWindowsHookEx` (WH_KEYBOARD_LL), `GetForegroundWindow`/`EnumWindows`, `BitBlt`/`GetDC`/`PrintWindow`
- Sysmon EID 1 (process create, parent lineage, signature) + EID 7 (image load: user32/gdi32 by unusual processes)
- Sysmon EID 11 (file create) — small periodic .jpg/.png/.dat/.log writes to temp/AppData working dirs
- Sysmon EID 3 / DNS + proxy logs — outbound beacon correlated to the capturing process (ties to HUNT-08)
- PowerShell script-block logs (keylogger implemented in PS)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — one process stacking surveillance primitives

```kusto
// Surface processes that combine window-enumeration + keyboard hook + screen-capture API use, then intersect on the same process
let lookback = 14d;
DeviceEvents
| where TimeGenerated > ago(lookback)
| where ActionType in ("SetWindowsHookExApiCall","GetAsyncKeyStateApiCall","ScreenCaptureApiCall","EnumWindowsApiCall")
| summarize prims = make_set(ActionType), primCount = dcount(ActionType),
           firstSeen = min(TimeGenerated) by DeviceName, InitiatingProcessFileName,
           InitiatingProcessSHA1, InitiatingProcessFolderPath
| where primCount >= 2                                 // stacked primitives, not a lone benign API
| join kind=leftouter (
    DeviceProcessEvents | summarize signed = anyif(InitiatingProcessVersionInfoCompanyName, isnotempty(InitiatingProcessVersionInfoCompanyName))
      by InitiatingProcessSHA1) on InitiatingProcessSHA1
| where InitiatingProcessFolderPath has_any (@"\temp\", @"\appdata\", @"\programdata\") or isempty(signed)
| order by primCount desc
```

## Triage guidance

- **Likely malicious:** an unsigned process from temp/AppData that both hooks the keyboard and captures the screen while enumerating foreground windows, then writes small periodic image/log files and beacons out; a PowerShell process performing keystroke capture with DNS-query construction; capture primitives on an IT/comms user's host with no corresponding remote-support/screen-share session.
- **Likely benign / expected:** screen-sharing/conferencing (Teams, Zoom), remote-support agents, IMEs, accessibility tools, clipboard/snipping utilities and password managers legitimately use these APIs. Baseline installed collaboration/support software per host and suppress signed known-good vendors.
- **Pivot next:** confirmed surveillance implant → capture memory/artifacts, identify the beacon destination (pivot HUNT-08 encrypted C2 / HUNT-07 cloud C2), determine what credentials/data were exposed, and escalate to IR — an active keylogger on a privileged user is a live compromise, not a backlog item.

## References

- https://www.clearskysec.com/siamesekitten/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1010/
