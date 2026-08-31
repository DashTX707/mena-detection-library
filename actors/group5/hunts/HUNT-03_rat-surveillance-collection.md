# Hunt: Commodity-RAT surveillance — keylogging, screen, audio and webcam capture

- **Hypothesis:** If Group5's njRAT/NanoCore implant is surveilling a Syrian-opposition victim, then a single non-interactive process running from an unexpected user-writable path (e.g. a masqueraded `dwm.exe` outside `System32`, or a decoy dropper) will exhibit a *stack* of collection behaviors that legitimate software rarely combines in one process: a global keyboard hook (keylogging), repeated GDI/`BitBlt` screen-capture calls, and access to microphone and camera capture devices — all correlated to the same RAT process lineage and paired with periodic C2 egress. The finding is the unexpected-relationship co-occurrence of keyboard-hook + screen + audio + video access under one non-media, non-conferencing process.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (collection)
  - T1113 — Screen Capture (collection)
  - T1123 — Audio Capture (collection)
  - T1125 — Video Capture (collection)
- **Actor procedure:** Group5's njRAT and NanoCore RATs gave operators keystroke/password logging, live screen viewing and screenshots, microphone activation to record surroundings, and webcam activation to capture video/images of Syrian-opposition targets — the core surveillance mission of the operation.
- **Why a hunt, not a rule:** Each capability in isolation (a keyboard hook, a `BitBlt`, a mic/camera open) is used constantly by benign software — conferencing apps, screenshot tools, IMEs — so any single-signal rule drowns in false positives. There is no discrete high-fidelity event for RAT keylogging or screen grabbing. The hunt value is in *correlating the co-occurrence* on one unexpected process with C2 egress, which demands per-host baselining of which processes legitimately touch each device — analyst work, not a standing alert.

## Data sources required

- Sysmon EID 1 / 4688 (process creation, image path, parent lineage, signature status)
- ETW / EDR sensor telemetry for API-callback behaviors: `SetWindowsHookEx` keyboard hooks, GDI screen-capture (`BitBlt`/`PrintWindow`), audio (WASAPI/`waveIn*`) and camera (MediaFoundation / `IMFMediaSource`) device opens
- Microphone/camera device-access audit (Windows capability access logs where available)
- Sysmon EID 3 (network connection) for correlated C2 egress

## Query starting point

Platform: `Splunk SPL`

```
index=edr (event_type="api_callback" OR event_type="device_access")
| eval cap=case(
    match(api,"SetWindowsHookEx.*WH_KEYBOARD"), "keylog",
    match(api,"(BitBlt|PrintWindow|GetDC|CreateCompatibleBitmap)"), "screen",
    match(api,"(waveInOpen|IAudioClient|IMMDevice.*Capture)") OR device_class="audio", "audio",
    match(api,"(MFCreateSourceReader|IMFMediaSource|FrameServer)") OR device_class="camera", "video",
    true(), null())
| where isnotnull(cap)
| stats dc(cap) as capability_types values(cap) as capabilities
        values(image_path) as image values(parent_image) as parent count by host, process_guid, process_name
| where capability_types >= 2
| join type=left process_guid
    [ search index=edr sourcetype=*network* event_type="connect"
      | stats values(dest_ip) as c2_candidates dc(dest_ip) as dest_count by process_guid ]
| where isnotnull(c2_candidates)
| sort - capability_types
```

## Triage guidance

- **Likely malicious:** One process combining two or more of {keylog, screen, audio, video} that is unsigned or masquerading (e.g. `dwm.exe` outside `C:\Windows\System32`, `putty.exe` from a temp/download path), has no interactive UI, and holds persistent outbound connections to a low-reputation host/port (historical Group5 C2 `88.198.222[.]163` on `8081`/`9999`). Keyboard hook + screenshot + camera on a non-conferencing process is a strong RAT signal.
- **Likely benign / expected:** Video-conferencing (Teams/Zoom/Webex) legitimately using mic+camera; screenshot/screen-recording utilities; accessibility tools and IMEs using keyboard hooks; signed vendor binaries from expected paths. Build a per-host allowlist of processes that normally touch each device before flagging.
- **Pivot next:** Confirm the process image against HUNT-02 (PAC Crypt / RAT family) and check masquerade path/signature (detection lane). If the surveillance-stacked process is confirmed as a RAT, treat the endpoint as an active compromise of a high-risk civil-society target and **escalate to incident-response** immediately; also run HUNT-04 for anti-forensic file deletion by the same lineage.

## References

- https://citizenlab.ca/2016/08/group5-syria/
- https://attack.mitre.org/groups/G0043/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1123/
- https://attack.mitre.org/techniques/T1125/
