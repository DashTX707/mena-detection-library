# Hunt: WIRTE collection, local staging & C2 exfil — LitePower screenshots to %AppData%, %ProgramData% working artifacts, POSTed back over the beacon

- **Hypothesis:** If LitePower is collecting from a host, then we should find a screenshot→stage→exfil chain co-located on one host: a PowerShell/script-host process using GDI/screen-capture APIs and writing image files to `%AppData%`, script/text working artifacts accumulating in `%ProgramData%` (`winrm.vbs`/`winrm.txt`/`regionh.txt`), and an outbound HTTP POST of that image/host data back to the same beaconing C2 — the collection and its exfil riding the existing web channel rather than a separate transfer.
- **ATT&CK:**
  - T1113 — Screen Capture (collection) — LitePower `Screenshot` function captures the screen, saves to `%AppData%`, POSTs to C2
  - T1074.001 — Data Staged: Local Data Staging (collection) — `%ProgramData%` working dir (`winrm.vbs`/`winrm.txt`/`regionh.txt`), `%AppData%` screenshot staging
  - T1041 — Exfiltration Over C2 Channel (exfiltration) — LitePower POSTs command output + screenshots; IronWind POSTs the host-profile inventory
- **Actor procedure:** LitePower includes a `Screenshot` function that captures the victim's screen, saves the image to `%AppData%`, and exfiltrates it to the C2 via HTTP POST. WIRTE uses `%ProgramData%` as a consistent working directory (`winrm.vbs`, `winrm.txt`, `regionh.txt`) to stage scripts and text artifacts before execution/exfil. Exfiltration rides the existing C2: LitePower returns command output and screenshots via HTTP POST, and IronWind POSTs its initial host-profile inventory to its collection endpoint — no separate exfil channel, so volume blends into the beacon.
- **Why a hunt, not a rule:** screenshotting has benign analogues (remote-support, screen-share, snipping tools), `%AppData%`/`%ProgramData%` are high-volume directories, and the exfil POST is indistinguishable from the C2 traffic it hides in — so no single event is alertable. The durable find (Summiting behavioral, Level 3) is the *chain on one entity*: a script host (not a screenshot app) invoking GDI capture → writing an image to `%AppData%` → a same-process HTTP POST of that image to a non-corporate destination, alongside script/text staging in `%ProgramData%`. Separating that from legitimate screen-capture and normal AppData churn requires baselining which processes legitimately capture the screen and where they store output — analyst correlation, not a threshold.

## Data sources required

- PowerShell script-block logging (EID 4104) — GDI/`CopyFromScreen`/`Graphics.CopyFromScreen`/`Bitmap`/`System.Drawing` screen-capture calls
- Sysmon EID 11 (file create) — image writes (`.jpg`/`.png`/`.bmp`) to `%AppData%`; `.vbs`/`.txt` staging in `%ProgramData%` (`winrm.*`, `regionh.txt`)
- Sysmon EID 1/3 + proxy — the process making an outbound POST and its destination, bytes-out
- EDR file + process-lineage telemetry

## Query starting point

Platform: `Splunk SPL`

```
(index=endpoint source="*PowerShell/Operational" EventCode=4104
   [| eval sb=lower(ScriptBlockText)
    | where match(sb,"copyfromscreen|system\.drawing|bitmap|graphics|createGraphics|\.save\(") ]
 )
| eval kind="screencap" | fields _time host ProcessGuid
| append [
    search index=endpoint source=*Sysmon* EventCode=11
    | eval f=lower(TargetFilename)
    | where (match(f,"(?i)\\\\appdata\\\\.*\.(jpg|jpeg|png|bmp)$"))
         OR (match(f,"(?i)\\\\programdata\\\\") AND match(f,"(winrm|regionh)\.(vbs|txt)$"))
    | eval kind="stage" | fields _time host ProcessGuid TargetFilename Image ]
| append [
    search index=proxy method=POST
    | where match(lower(process_name),"(powershell|wscript|cscript)\.exe$")
    | eval kind="exfil_post" | fields _time host process_name dest_host bytes_out ]
| bin _time span=15m
| stats dc(kind) as stages values(kind) as seen values(TargetFilename) as files 
        values(dest_host) as dsts by _time, host
| where stages>=2
```

Any host showing >=2 of {screencap, stage-write, exfil POST} in one 15-min window is a lead; confirm the exfil POST destination against the C2 hunt (HUNT-08).

## Triage guidance

- **Likely malicious:** a PowerShell/script-host process (not a screenshot/RMM app) calling `CopyFromScreen`/`System.Drawing` and saving an image to `%AppData%`, then POSTing it out; `winrm.vbs`/`winrm.txt`/`regionh.txt` in `%ProgramData%`; an outbound POST from `powershell.exe`/`wscript.exe` to a non-corporate/themed destination with image-sized payloads on the beacon cadence.
- **Likely benign / expected:** legitimate RMM/screen-share/snipping tools capturing the screen; apps caching images in `%AppData%`; backup/sync clients POSTing data to known SaaS. Baseline the processes that legitimately capture the screen and your sanctioned upload destinations and suppress.
- **Pivot next:** tie the collecting process back to the LitePower stager and its persistence (HUNT-04) and recon (HUNT-07), and the exfil POST to the C2 channel (HUNT-08). In the SameCoin context, the same `%ProgramData%` staging and `csrs.exe` InfectOutlook/InfectAD spread (T1534/T1570, detection lane) widen the blast radius — pivot there if `csrs.exe` is present. Confirmed screenshot exfil on a live host is an active espionage intrusion — escalate to incident-response-coordinator.

## References

- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://attack.mitre.org/groups/G0090/
