# Hunt: Dark Caracal — low-signal native-API recon & collection burst by a single non-interactive process (Bandook RAT)

- **Hypothesis:** Once Bandook is resident (hollowed inside `iexplore.exe`), its individual actions are each too quiet to alert on — it uses native Windows API calls for the injection/reconstruction sequence and then drives a *burst* of low-signal discovery and collection commands: enumerate drives/devices, list files in default directories, look up the public IP, grab a screenshot, hook the keyboard, touch the microphone/webcam. No single API call is suspicious; the finding is the **stack on one non-interactive process** — the same short-lived process performing memory-write/thread-context injection APIs *and then* a recon+collection cluster (drive enum + public-IP lookup + screen/keyboard/mic/cam access) within a tight window, with no interactive user driving it. If Bandook is here, that behavioral cluster exists even after the network IOCs have rotated.
- **ATT&CK:**
  - T1106 — Native API (execution) — Bandook's Delphi loader and RAT drive reconstruction, process hollowing, and its discovery/collection commands through direct native API calls; hunt via API-sequence/behavioral analytics rather than any single call

- **Actor procedure:** The Delphi loader reconstructs Bandook in memory and process-hollows it into `iexplore.exe` using native API (`CreateProcess` suspended → `NtUnmapViewOfSection`/unmap → `WriteProcessMemory` → `SetThreadContext`/`ResumeThread`). The resident RAT then services operator commands that are themselves native-API-backed and, on their own, mundane: `@0004` list drives / peripheral enumeration, `@0005` file listing from default directories, `@0011` retrieve public IP, `@0003` screenshot (BitBlt/GDI), keylogging via low-level keyboard hooks (`SetWindowsHookEx`), plus microphone and webcam capture, before uploading via `@0006`. The full ~120-command build extends this with Python/Java payload execution. The individually-common APIs, invoked in sequence by one non-interactive process, are the durable behavioral tell (Summiting technique/implementation-core, robust to IOC rotation).
- **Why a hunt, not a rule:** Every primitive here — `WriteProcessMemory`, a screenshot, a keyboard hook, a public-IP lookup, drive enumeration — is used constantly by legitimate software (installers, conferencing apps, backup tools, remote-support agents), so any single-API rule is drowned in false positives. The threat only appears in the *combination and sequencing on one process without interactive context*: injection APIs followed by a recon+collection burst by a process that no user is driving. Building that multi-API behavioral correlation, tuning the window, and excluding the legitimate multi-capability apps (conferencing, RMM) is judgement-heavy hunt work. If a specific robust sub-sequence proves reliably separable from benign software (e.g. hollow-into-`iexplore.exe` immediately followed by keyboard-hook + BitBlt by the same PID), hand *that* to detection-engineering as a scoped behavioral analytic — this hunt is where you discover whether such a sub-sequence is clean enough to promote.

## Data sources required

- EDR behavioral / API telemetry (Defender for Endpoint, CrowdStrike, SentinelOne): process-injection events (`WriteProcessMemory`/`SetThreadContext` into another process), API-hook installation, screen-capture, audio/camera device access, keyed to the initiating PID
- Sysmon: EID 1 (process create, lineage), EID 8 (CreateRemoteThread), EID 10 (ProcessAccess with `GrantedAccess` consistent with injection), EID 3 (public-IP-lookup egress)
- EDR file-write telemetry: keylog buffer files, screenshot temp files written by a non-interactive process
- Session/interactivity context: whether an interactive user session is driving the process (to isolate non-interactive/background actors)

## Query starting point

Platform: `KQL / Microsoft Defender for Endpoint` — find one process that both injects and then performs a multi-capability collection burst, with no interactive owner.

```kusto
let window = 10m;
// (a) injection / native-API memory events (hollowing candidates, esp. into iexplore.exe)
let inject = DeviceEvents
    | where Timestamp > ago(14d)
    | where ActionType in ("CreateRemoteThreadApiCall","WriteToLsassProcessMemory","ProcessInjection",
                           "SetThreadContextRemoteApiCall","NtUnmapViewOfSectionApiCall")
          or (ActionType == "ProcessAccess" and AdditionalFields has "0x1F")
    | project injTime = Timestamp, DeviceName, PidHint = InitiatingProcessId,
              InitiatingProcessFileName, TargetProcess = FileName;
// (b) collection / discovery capability events
let collect = DeviceEvents
    | where Timestamp > ago(14d)
    | where ActionType in ("ScreenshotTaken","GetAsyncKeyState","SetWindowsHookEx",
                           "MicrophoneAccess","CameraAccess","SensitiveApiCall")
          or ActionType has_any ("ScreenCapture","AudioCapture","KeyLog")
    | project colTime = Timestamp, DeviceName, PidHint = InitiatingProcessId, Capability = ActionType;
inject
| join kind=inner collect on DeviceName, PidHint
| where abs(datetime_diff('second', colTime, injTime)) <= 600
| summarize capabilities = make_set(Capability), captures = count(),
            span = max(colTime) - min(colTime)
         by DeviceName, PidHint, InitiatingProcessFileName, TargetProcess, injTime
| where array_length(capabilities) >= 3   // inject + >=3 distinct collection capabilities = burst
| order by array_length(capabilities) desc
```

## Triage guidance

- **Likely malicious:** one non-interactive process that performs an injection/memory-write sequence (especially producing a hollowed `iexplore.exe` with an anomalous parent) and then, within minutes, stacks three or more collection capabilities (screenshot + keyboard hook + mic/camera) plus drive enumeration and a public-IP lookup; a keylog/screenshot buffer file written by that process; the process later uploading to a Dark Caracal C2 over Base64+`&&&&` HTTP (correlate detection pack T1071.001).
- **Likely benign / expected:** conferencing apps (Teams/Zoom/Webex) legitimately touch screen, mic and camera; RMM/remote-support agents (screen + input); backup/AV/EDR products enumerate drives and inject/hook by design; installers use memory-write APIs. Baseline and allowlist these signed, interactive-or-known multi-capability apps — the discriminator is a *non-interactive, unexpected, or hollowed* process doing injection **and** a broad collection burst it has no reason to.
- **Pivot next:** a confirmed inject-then-collect burst on a non-interactive process is a live Bandook implant — capture the process image and check for the AES-CFB IV / opcode fingerprint (HUNT-01), pull Run-key persistence (T1547.001), trace the loader chain back to the cloud fetch (HUNT-02) and the delivery document, and escalate to incident-response-coordinator. Assess whether the hollow-`iexplore.exe`→keyboard-hook+BitBlt sub-sequence is clean enough to promote to detection-engineering.

## References

- https://research.checkpoint.com/2020/bandook-signed-delivered/
- https://attack.mitre.org/groups/G0070/
- https://attack.mitre.org/techniques/T1106/
