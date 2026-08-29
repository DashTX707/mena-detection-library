# Hunt: WIRTE COM-hijacking persistence (flagship stealth) — HKCU CLSID\LocalServer32 pointing at a malicious winrm.vbs/slmgr.vbs

- **Hypothesis:** If WIRTE's Ferocious stager has established its signature persistence on a host, then we should find a user-hive COM hijack that legitimate software effectively never creates: a write to `HKCU\Software\Classes\CLSID\{...}\LocalServer32` (or `InprocServer32`) whose default value points at a `.vbs`/script in a user-writable path (`%ProgramData%`, `%AppData%`) — hijacking the `Scripting.Dictionary` COM object — followed later by `wscript`/`cscript` executing `winrm.vbs`/`slmgr.vbs` from that path under `explorer.exe` or a scheduled-task trigger. Known CLSIDs `{50236F14-2C02-4291-93AB-B5A80F9666B0}` and `{14C34482-E07F-44CF-B261-385B616C54EC}` are pivots, not the anchor.
- **ATT&CK:**
  - T1546.015 — Event Triggered Execution: Component Object Model Hijacking (persistence) — HKCU CLSID `LocalServer32` referencing a malicious VBS to hijack `Scripting.Dictionary`
- **Actor procedure:** The Ferocious VBS stager adds a Class ID under `HKCU\Software\Classes\CLSID\{...}\LocalServer32` referencing the malicious `winrm.vbs`, hijacking the `Scripting.Dictionary` COM object so the VBS is invoked whenever a program/script (including the legitimate `winrm.vbs`/`slmgr.vbs`) references that programmatic ID. A LitePower-created scheduled task later triggers a `Scripting.Dictionary` COM program, activating the hijack. Observed CLSIDs include `{50236F14-...}` and `{14C34482-...}`. This runs in the user hive, requires no admin, and survives reboot silently.
- **Why a hunt, not a rule:** HKCU `Classes\CLSID` sees heavy benign churn (per-user COM registration by legitimate apps), so a blanket alert on CLSID writes drowns the SOC — this is the actor's most deliberately stealthy persistence for exactly that reason. The high-fidelity, durable discriminator is *content, not the key*: a `LocalServer32`/`InprocServer32` default value that resolves to a script (`.vbs`/`.js`) or an executable in a user-writable staging directory, rather than a signed binary in Program Files/System32. That value-path judgement, and correlating it with later script-host execution and scheduled-task triggers, is analyst work over a noisy key space — a hunt that, once baselined, can graduate a tight registry-write analytic to detection-engineering.

## Data sources required

- Sysmon EID 12/13 (registry key/value set) on `HKCU\Software\Classes\CLSID\*\{Local,Inproc}Server32` — the anchor
- Sysmon EID 1 / 4688 — `wscript.exe`/`cscript.exe` executing `winrm.vbs`/`slmgr.vbs` from `%ProgramData%`/`%AppData%`, parent `explorer.exe` or `taskeng`/`svchost` (task trigger)
- Sysmon EID 11 — creation of the referenced `.vbs` in the staging path
- Scheduled-task telemetry (EID 4698 / Task Scheduler operational) referencing a `Scripting.Dictionary` COM trigger — ties to HUNT-07/detection lane
- Autoruns/registry snapshot diffs for retro-hunt across the fleet

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* (EventCode=12 OR EventCode=13)
| eval key=lower(TargetObject), val=lower(Details)
| where match(key,"\\\\classes\\\\clsid\\\\\{.*\}\\\\(localserver32|inprocserver32)")
| eval bad_path=if(match(val,"(?i)\\\\(programdata|appdata|users\\\\public|temp)\\\\") 
                   OR match(val,"(?i)\.(vbs|js|wsf|hta)(\b|$)"),1,0)
| eval known_clsid=if(match(key,"50236f14-2c02-4291-93ab-b5a80f9666b0")
                      OR match(key,"14c34482-e07f-44cf-b261-385b616c54ec"),1,0)
| where bad_path=1 OR known_clsid=1
| table _time host User key val bad_path known_clsid Image
```

Pivot each hit forward to Sysmon EID 1 for `wscript`/`cscript` executing the referenced script (esp. `winrm.vbs`/`slmgr.vbs`) and to scheduled tasks triggering `Scripting.Dictionary`; retro-hunt the same CLSID/value pattern fleet-wide with an Autoruns sweep.

## Triage guidance

- **Likely malicious:** any `HKCU ...\CLSID\{...}\LocalServer32` default value resolving to a `.vbs`/script or a binary under `%ProgramData%`/`%AppData%`/`%public%`; the specific CLSIDs above at any path; a CLSID write immediately followed by `wscript` running `winrm.vbs`/`slmgr.vbs`; a scheduled task that references a `Scripting.Dictionary` COM program pointing back to a user-writable script.
- **Likely benign / expected:** legitimate per-user COM registration by installed applications pointing `LocalServer32` at a signed EXE in Program Files; developer/COM-add-in registrations. Baseline the set of CLSID values that normally appear and suppress signed-Program-Files targets.
- **Pivot next:** confirm the referenced VBS (HUNT-03 execution, HUNT-09 staging in `%ProgramData%`), the LitePower scheduled task that triggers it, and the C2 the stager beacons to (HUNT-08). Hijacked `Scripting.Dictionary` persistence on a live host is a confirmed foothold — escalate to incident-response-coordinator and, given the low-noise value-path discriminator, hand a scoped `LocalServer32`→user-writable-script registry analytic to detection-engineering.

## References

- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://attack.mitre.org/groups/G0090/
