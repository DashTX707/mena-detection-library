# Hunt: Volatile Cedar — local espionage staging before HTTP exfil

- **Hypothesis:** If an Explosive implant is collecting on one of our hosts, then between capture and exfil it stages its espionage artifacts locally — captured keystrokes, screenshots and pulled files written to a working directory before the RAT ships them over HTTP(S) to C2. On a web/app server that has no interactive desktop user, the tell is anomalous: a *non-browser, non-deploy process writing a growing cluster of small files* (keylog logs, image/`.dat` blobs) into a temp or application-adjacent directory on a cadence, with little-to-no legitimate reader — a staging cache, not a working data set. The finding stacks *unexpected file-write relationship* (a server-role process producing user-collection artifacts like screenshots on a headless box) + *volume/cadence* (steady small writes accumulating in one directory) on a host that should never generate desktop-capture output at all.
- **ATT&CK:**
  - T1074.001 — Data Staged: Local Data Staging (collection) — keystrokes, screenshots and collected files staged locally in the Explosive working directory prior to HTTP exfil

- **Actor procedure:** The Explosive RAT captures keystrokes (keylogging) and desktop screenshots and collects files of interest, then — per Check Point — stages that captured material locally on the compromised host before exfiltrating it over its HTTP(S) C2 channel. Because the group's primary victims are internet-facing servers (telecoms, ISPs, hosting), screenshot/keylog artifacts accumulating on a headless server are a strong role-mismatch signal: those hosts have no interactive user whose screen or keystrokes there would be anything legitimate to capture.
- **Why a hunt, not a rule:** Local staging of small espionage artifacts leaves little discrete signal — a file write is the most common event in any system, and temp-directory writes are constant background noise, so a standalone "file written to temp" rule is meaningless. The finding only emerges from correlating *which process* is writing, *what kind* of artifact (capture-shaped), and *whether the host role* makes that output legitimate — plus the accumulation cadence. That role-aware baselining and multi-attribute correlation is hunt work, not an alertable primitive.

## Data sources required

- EDR file-creation telemetry with initiating process (path, filename, size, writing process, account)
- Process-role / asset inventory (which hosts are headless servers vs. interactive workstations)
- Screen-capture / keyboard-hook behavioral telemetry from EDR (corroborates the collection source)
- Directory-growth / file-count-over-time analytics on temp and application-working paths

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — cluster small file writes by a single non-standard process into one directory on a server-role host.

```kusto
let serverHosts = toscalar(
    DeviceInfo
    | where DeviceType == "Server" or OSPlatform startswith "WindowsServer"
    | summarize make_set(DeviceName));
DeviceFileEvents
| where TimeGenerated > ago(14d)
| where ActionType == "FileCreated"
| where DeviceName in (serverHosts)                       // headless: no legit screen/keystroke capture
| where FolderPath has_any ("\\Temp\\","\\AppData\\","\\ProgramData\\","\\webapps\\","\\Windows\\Temp\\")
| where FileName matches regex @"(?i)\.(dat|log|bin|jpg|jpeg|bmp|png|tmp|kl)$"
| where InitiatingProcessFileName !in~ ("msedge.exe","chrome.exe","OfficeClickToRun.exe","TiWorker.exe","MsMpEng.exe")
| summarize file_count = count(),
            total_bytes = sum(FileSize),
            distinct_names = dcount(FileName),
            first = min(TimeGenerated), last = max(TimeGenerated),
            sample = make_set(FileName, 15)
        by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, FolderPath
| extend window_hours = round((last-first)/1h,1)
| where file_count >= 20 and total_bytes < 50000000        // many small artifacts accumulating = staging cache
| order by file_count desc
```

## Triage guidance

- **Likely malicious:** a headless server accumulating screenshot-shaped (`.jpg`/`.bmp`/`.png`) or keylog-shaped (`.log`/`.kl`/`.dat`) files written by a non-browser, non-deploy process into one temp/working directory on a cadence, with no legitimate reader; a staging directory on a host that also appears in the C2 (HUNT-03), obfuscation (HUNT-04) or web-shell lanes; capture artifacts on a box with no interactive desktop session at all. Role-mismatch (desktop-capture output on a server) plus steady accumulation is the finding.
- **Likely benign / expected:** application/server log rotation, cache directories, backup-job scratch space, crash dumps, and monitoring-agent spool files legitimately write many small files — baseline the writing process and directory; image thumbnails and report-generation temp files on app servers; deploy/CI scratch. A known service writing to its own documented spool is expected; an unknown process producing capture-shaped artifacts on a headless host is not.
- **Pivot next:** identify and hash the writing process, and check EDR for screen-capture / keyboard-hook behavior from it (corroborates Explosive collection); inspect the staged files' entropy and run the obfuscation hunt (HUNT-04) — staged espionage data is often encoded before exfil; correlate write cadence with outbound beacons in the C2 hunt (HUNT-03) to catch the stage→exfil rhythm. If files decode to captured victim data, this is active espionage — escalate to incident-response-coordinator and preserve the staging directory.

## References

- https://blog.checkpoint.com/security/volatilecedar/
- https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
- https://attack.mitre.org/techniques/T1074/001/
