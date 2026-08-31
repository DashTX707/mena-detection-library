# Hunt: Co-resident collection suite — keylogging, activity-triggered screenshots, microphone audio on one host

- **Hypothesis:** If a Madi-style Delphi infostealer is resident, then a single non-browser process (historically `iexplore.exe` masquerading from a user-profile path) will exhibit the *stacked* collection behaviours of Madi's backdoor at once — low-level keyboard hooking, screen capture that fires when the user touches webmail/IM/social apps, and microphone recording written to WAV — so the same PID will show keyboard-hook API use, GDI/screen-capture activity correlated with browser focus, and audio-device access plus WAV file creation. A single one of these is noisy; the three co-resident on one non-media process is the finding.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (collection)
  - T1113 — Screen Capture (collection)
  - T1123 — Audio Capture (collection)
- **Actor procedure:** Madi's Delphi backdoor logged keystrokes, captured screenshots on both a timed interval and event-triggered when the victim interacted with Gmail, Hotmail, Yahoo Mail, ICQ, Skype, Google+ or Facebook, and recorded microphone audio to WAV files staged for HTTP exfil — nine core functions running under a single implanted process.
- **Why a hunt, not a rule:** Keyboard-hook (`SetWindowsHookEx`), screen-grab (GDI/BitBlt) and mic (`waveInOpen`) APIs are used by legitimate software (conferencing, accessibility, capture tools), so no single API call is alertable. The durable, evasion-resistant signal is the *unexpected co-residency* — one process that is not a known media/collab app doing all three — which requires per-host baselining of which processes legitimately touch audio/screen/keyboard, not a static rule.

## Data sources required

- Sysmon EID 1 / Security 4688 (process creation, image path, parent) to identify the candidate process
- EDR API-telemetry / ETW (Microsoft-Windows-Win32k, audio capture events, `SetWindowsHookEx` / `waveInOpen` / `BitBlt` calls) keyed by PID
- Sysmon EID 11 (file create) for `.wav` writes and screenshot image writes into user-profile/temp/staging dirs
- Baseline: hunting-wiki list of processes that legitimately use mic/screen/keyboard hooks

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=11)
| eval fn=lower(TargetFilename)
| where match(fn,"\.(wav|bmp|jpg|jpeg|png|scr)$")
      AND match(fn,"(\\\\users\\\\|\\\\documents and settings\\\\|\\\\temp\\\\|\\\\appdata\\\\)")
| stats dc(fn) as capture_files values(fn) as files by host, Image
| join type=inner host Image [
    search index=endpoint (EventCode=7 OR EventCode=12 OR sourcetype=etw)
      (ImageLoaded="*\\winmm.dll" OR ImageLoaded="*\\gdi32*.dll" OR api IN ("SetWindowsHookEx","waveInOpen","BitBlt"))
    | stats values(coalesce(api,ImageLoaded)) as collect_apis by host, Image ]
| where capture_files>0
| table host Image capture_files files collect_apis
```

## Triage guidance

- **Likely malicious:** One non-browser/non-media process writing `.wav` plus screenshot images into a user-profile or temp directory, with keyboard-hook and audio APIs on the same PID; screenshot writes time-correlated with the user opening webmail/IM/social sites; process image is `iexplore.exe` (or similar) running from `...\Templates`, `...\Printhood` or another user path rather than Program Files.
- **Likely benign:** Teams/Zoom/OBS/Snip & Sketch/accessibility tools legitimately using mic+screen+keyboard — suppress via the baseline of approved collab/capture apps. A single lone capability (screenshots only) with a known parent is not the finding.
- **Pivot next:** Confirm the process image path and parent (correlate with HUNT-02 staging and the T1036.005 masquerade lane). If keylog/screenshot/WAV staging is confirmed on one host, treat as live compromise and **escalate to incident-response**.

## References

- https://securelist.com/the-madi-campaign-part-i-5/33693/
- https://securelist.com/the-madi-campaign-part-ii/33701/
- https://attack.mitre.org/techniques/T1056/001/
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1123/
