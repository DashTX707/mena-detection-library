# Hunt: MarkiRAT in-memory host discovery (AV fingerprinting, process/window/language enumeration)

- **Hypothesis:** If a MarkiRAT implant is running from its `%PUBLIC%\AppData\Windows` repository (or from a Startup/Telegram/Chrome-hijacked launch), then within a tight process-lineage window it will fingerprint the host — enumerating running processes to spot security products (`exe.exe`=Kaspersky, `bdagent.exe`=Bitdefender), locating and terminating the KeePass process, checking for the Persian keyboard layout (locale `0x0429`) before keylogging, and reading foreground window titles — so an unsigned/user-writable-path process that both queries `GetKeyboardLayout`/tasklist-style APIs and terminates `keepass.exe` is an unexpected-relationship + PCR-deviation anomaly no single benign process should exhibit together.
- **ATT&CK:**
  - T1518.001 — Software Discovery: Security Software Discovery (discovery)
  - T1057 — Process Discovery (discovery)
  - T1614.001 — System Location Discovery: System Language Discovery (discovery)
  - T1010 — Application Window Discovery (discovery)
- **Actor procedure:** MarkiRAT enumerates the process list to report installed AV to C2 via a `k` parameter (`1` for Kaspersky, `3` for Bitdefender), and enumerates processes again to find and kill KeePass so the victim re-enters the master password for capture. It checks for the Persian keyboard layout (0x0429) to gate keystroke logging to Iran-based victims, and harvests active window titles into the initial C2 registration POST (`<b>Windows Title1</b>...`).
- **Why a hunt, not a rule:** Each behavior on its own — process enumeration, `GetKeyboardLayout`, `GetForegroundWindow` — is ubiquitous and benign; there is no reliable discrete host event for any of them, so a rule would drown in noise. The hunt value is the *stack*: these API behaviors concentrated in one unsigned process running from a user-writable path, especially co-occurring with a `keepass.exe` termination. That combination requires per-host baselining and EDR API-behavior telemetry rather than a precise alert.

## Data sources required

- EDR API-behavior / sensor telemetry (process-enumeration, `GetKeyboardLayout`, `GetForegroundWindow`, `EnumWindows` calls) attributed to a process image + signer
- Sysmon EID 1 / 4688 (process create) — image path, signature status, parent
- Sysmon EID 5 / 4689 (process terminate) and EID 10 (process access) targeting `keepass.exe`

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=1 OR EventCode=4688)
| eval img=lower(coalesce(Image,New_Process_Name))
| where match(img,"\\\\(users\\\\public|appdata|temp)\\\\") AND Signed!="true"
| rename process_guid as pguid
| join type=inner pguid [
    search index=edr (behavior="process_enumeration" OR behavior="get_keyboard_layout"
                      OR behavior="get_foreground_window" OR api="EnumProcesses")
    | stats values(behavior) as behaviors dc(behavior) as behavior_variety by pguid ]
| join type=left pguid [
    search index=endpoint (EventCode=10 OR EventCode=5) TargetImage="*\\keepass.exe"
    | eval keepass_touched="yes" | fields pguid keepass_touched ]
| where behavior_variety>=2 OR keepass_touched="yes"
| table _time host img behaviors keepass_touched ParentImage
```

## Triage guidance

- **Likely malicious:** An unsigned process from `\Users\Public\`, `\AppData\`, or a Telegram/Chrome data directory that enumerates processes AND queries keyboard layout AND/OR terminates `keepass.exe`; the same process later writing an `nfo` keystroke log or `scr.jpg` (pivot to HUNT-02); parent is `WINWORD.EXE`, a hijacked Telegram/Chrome `.lnk`, or `svehost.exe`.
- **Likely benign / expected:** Endpoint security agents, password managers, and IME/localization utilities legitimately query keyboard layout and window titles; signed installers enumerate processes. Baseline the signed processes on each host that legitimately touch KeePass or read layouts and suppress them.
- **Pivot next:** Confirm the implant image, then pivot to HUNT-02 (keylog/clipboard `nfo` artifact) and HUNT-03 (file discovery/exfil). If a running MarkiRAT implant is confirmed, this is a live compromise — **escalate to incident-response** and preserve the `%PUBLIC%\AppData\Windows` repository and mutex `Global\{2194ABA1-BFFA-4e6b-8C26-D1BB20190312}`.

## References

- https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/
- https://www.picussecurity.com/resource/blog/ferocious-kitten-apt-exposed-inside-the-iran-focused-espionage-campaign
- https://attack.mitre.org/techniques/T1518/001/
- https://attack.mitre.org/techniques/T1614/001/
