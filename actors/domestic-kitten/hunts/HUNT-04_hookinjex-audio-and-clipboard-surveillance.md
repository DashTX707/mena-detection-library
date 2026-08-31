# Hunt: HookInjEx local surveillance — surreptitious audio and clipboard capture on Windows

- **Hypothesis:** If the HookInjEx Windows stealer (or FurBall on a Windows-companion vector) is active, then a non-media, non-productivity process — typically code injected into `explorer.exe` — will open audio-capture endpoints and read the clipboard repeatedly without a user-facing UI reason (an unexpected-relationship + improper-timing anomaly), producing short ~60-second audio recordings and periodic clipboard reads.
- **ATT&CK:**
  - T1123 — Audio Capture (collection)
  - T1115 — Clipboard Data (collection)
- **Actor procedure:** The HookInjEx C++ stealer records roughly 60 seconds of audio from the host microphone and steals clipboard data (the Rampant Kitten Android backdoor separately records ~30s of surroundings audio, masked by a fake "Google protect is enabled" notification). HookInjEx runs its logic from a DLL mapped into `explorer.exe`, so the audio/clipboard access originates from a trusted process rather than a standalone binary.
- **Why a hunt, not a rule:** Microphone and clipboard access are extremely common in benign software (conferencing, dictation, clipboard managers) and audio/clipboard API calls are near-invisible without behavioral EDR, so a naive "process touched the mic" rule would drown in noise. The hunt keys on the anomalous actor — audio + clipboard access attributed to `explorer.exe` or another process with no legitimate media/clipboard role — which requires per-environment baselining of who normally records audio, and is far more durable than any HookInjEx file hash.

## Data sources required

- EDR audio/microphone-access events (process, device endpoint, duration)
- EDR / API-monitoring clipboard-read events (`GetClipboardData`, `OpenClipboard` by process)
- Sysmon EID 7 (image load) and EID 8 (CreateRemoteThread) to attribute activity to injected `explorer.exe`
- Process baseline of normal audio/clipboard consumers

## Query starting point

Platform: `Microsoft Sentinel / Defender KQL`

```kql
// Audio-capture attributed to an unexpected process (esp. explorer.exe)
let mic = DeviceEvents
| where ActionType in ("MicrophoneAccess","SensitiveResourceAccess","AudioCaptureStarted")
| where InitiatingProcessFileName has_any ("explorer.exe","svchost.exe","rundll32.exe","regsvr32.exe")
    or InitiatingProcessFolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType;
// Clipboard reads by the same/unexpected processes
let clip = DeviceEvents
| where ActionType in ("ClipboardRead","GetClipboardData")
| where InitiatingProcessFileName in~ ("explorer.exe","rundll32.exe","regsvr32.exe","svchost.exe")
| project Timestamp, DeviceId, InitiatingProcessFileName, ActionType;
mic
| join kind=inner (clip) on DeviceId
| summarize AudioEvents=count(), ClipEvents=dcount(Timestamp1),
    procs=make_set(InitiatingProcessFileName) by DeviceId
| where AudioEvents > 0 and ClipEvents > 0
| sort by AudioEvents desc
```

## Triage guidance

- **Likely malicious:** `explorer.exe` (or `rundll32`/`regsvr32`/an unsigned module) opening the microphone for short fixed intervals AND reading the clipboard, with no conferencing/dictation app in the foreground; correlated with HUNT-05 DLL-injection into `explorer.exe`; recordings written to a temp/AppData path then archived (HUNT-06).
- **Likely benign:** Teams/Zoom/Webex, dictation, and clipboard-manager utilities recording audio/reading clipboard under their own signed process; RDP clipboard redirection. Baseline sanctioned media/clipboard apps and exclude them.
- **Pivot next:** If `explorer.exe` is the audio/clipboard actor, pivot to the DLL-injection hunt (Rampant Kitten HookInjEx explorer.exe injection — detection lane) and HUNT-06 exfil; confirm the injected module's signature. On confirmation, **escalate to incident-response**.

## References

- https://research.checkpoint.com/2020/rampant-kitten-an-iranian-espionage-campaign/
- https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1115/
