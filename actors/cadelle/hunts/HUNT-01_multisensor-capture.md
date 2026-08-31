# Hunt: Cadelspy multi-sensor capture — screenshots, webcam, microphone, and clipboard from one process

- **Hypothesis:** If Backdoor.Cadelspy is resident on a host, then a single non-media background process will read multiple human-input sensors — grabbing screenshots/webcam frames, opening the microphone, and reading the clipboard — and stage the results as image/audio/text artifacts under a user-writable path. The durable anomaly is an unexpected relationship: one untrusted process concurrently touching the camera device, the audio-capture device, GDI screen-copy, and the clipboard, which legitimate single-purpose apps do not do together.
- **ATT&CK:**
  - T1113 — Screen Capture (collection)
  - T1123 — Audio Capture (collection)
  - T1115 — Clipboard Data (collection)
- **Actor procedure:** Cadelspy captures screenshots of the victim desktop and takes photos through the computer's webcam, records audio from the system microphone to eavesdrop on the environment, and steals the contents of the Windows clipboard (copied passwords, URLs, message fragments). These streams are collected continuously as part of broad surveillance and later compressed into `.cab` archives for exfiltration.
- **Why a hunt, not a rule:** Each capture primitive alone (a `GetClipboardData` call, a `BitBlt`, opening `wave`/camera device) uses standard OS APIs shared with legitimate software — conferencing, screenshot utilities, backup tools — so any single signal is far too noisy to alert on. The hunt value is the *stacked* composite on one process plus per-host baselining of which processes are legitimately allowed to touch camera/mic. Attackers can rename the binary and change file paths (Summiting Level 1 IOCs), but the technique-core behavior — one process fanning across screen+cam+mic+clipboard — is expensive to abandon, so hunt that relationship, not the strings.

## Data sources required

- Sysmon EID 1 / Security 4688 — process creation, image path, parent, signature status
- Microphone/camera device access telemetry — Windows `CapabilityAccessManager` ConsentStore registry writes (`HKCU\...\ConsentStore\microphone|webcam\NonPackaged`), or EDR device-access events for `\Device\KSENUM` / MMDevice / DirectShow capture handles
- Sysmon EID 11 — file writes of image (`.bmp`,`.jpg`,`.png`), audio (`.wav`,`.tmp`), and text artifacts to user-profile / temp locations
- EDR API-telemetry (where available) — clipboard reads (`GetClipboardData`/`OpenClipboard`) and GDI screen-copy attributed to a process

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=1 OR EventCode=4688)
| eval proc=lower(coalesce(Image,New_Process_Name))
| eval signed=coalesce(Signed,SignatureStatus,"unknown")
``` establish the untrusted-process set ```
| search NOT proc IN ("*\\teams.exe","*\\zoom.exe","*\\ms-teams.exe","*\\slack.exe","*\\snippingtool.exe","*\\screenclippinghost.exe","*\\obs64.exe")
| eval prockey=coalesce(process_guid,ProcessGuid,proc)
| join type=inner prockey [
    ``` sensor-access + staging evidence for the same process ```
    search index=endpoint (EventCode=11 (TargetFilename="*.bmp" OR TargetFilename="*.jpg" OR TargetFilename="*.png" OR TargetFilename="*.wav"))
      OR (EventCode=13 TargetObject="*\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged*")
      OR (EventCode=13 TargetObject="*\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged*")
      OR (index=edr api IN ("GetClipboardData","OpenClipboard","capCreateCaptureWindow","BitBlt"))
    | eval prockey=coalesce(process_guid,ProcessGuid,lower(coalesce(Image,New_Process_Name)))
    | stats values(api) as apis values(TargetObject) as consent_writes
            values(TargetFilename) as staged_files dc(EventCode) as evt_types by prockey ]
| eval sensor_hits=mvcount(mvappend(apis,consent_writes))
| where sensor_hits>=2
| table host, proc, signed, apis, consent_writes, staged_files
```

## Triage guidance

- **Likely malicious:** One unsigned/unusually-located process that reads the clipboard AND has webcam/microphone ConsentStore entries AND stages `.bmp`/`.jpg`/`.wav` files to a temp or user-profile folder; capture cadence that is periodic/timer-driven regardless of user presence; the same process later feeding a `.cab` staging folder (see HUNT-03 / T1560).
- **Likely benign / expected:** Video-conferencing (Teams, Zoom, Webex), OS screenshot tools, password managers that legitimately read the clipboard, backup/DLP agents, and vendor camera utilities — baseline these per host and suppress. A single sensor touched by a well-known signed app is not a finding.
- **Pivot next:** If confirmed, pull the process's full file-write set and look for `.cab` archiving (T1560) and print-spool/USB monitoring (HUNT-03, T1120). Treat a live multi-sensor surveillance process as an active compromise and **escalate to incident-response-coordinator**. Hand the stable composite (one process → screen+cam+mic+clipboard) to detection-engineering as a candidate correlation rule.

## References

- https://attack.mitre.org/software/S0454/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1115/
- https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east/
- https://securityaffairs.com/42641/breaking-news/cadelle-and-chafer-iranian-hackers.html
