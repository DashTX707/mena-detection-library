# Hunt: StrongPity — hidden-window execution of dropped components in persistence context

- **Hypothesis:** If a StrongPity component is running on a host, then it operates **without a visible UI** — its processes run with a hidden window so the victim never sees them on the desktop — and, taken alone, hidden-window execution is nearly signal-free (countless legitimate background processes have no window). The hypothesis therefore keys on **unexpected-relationship stacking**: a process running hidden AND launched from a `%temp%`/`lang_*` or masqueraded path AND referenced by a persistence mechanism (an HKCU Run value like *Help Manager*, a service, or a scheduled task) AND lacking a trusted signature. Hidden-window is the connective tissue that ties an otherwise-ordinary background process to the StrongPity persistence story; the finding is the *cluster*, never the hidden window by itself.
- **ATT&CK:**
  - T1564.003 — Hide Artifacts: Hidden Window (stealth) — components run with hidden windows to operate invisibly on the victim desktop; hunt combined with lineage + persistence context.

- **Actor procedure:** Per S0491, StrongPity components execute with hidden windows to avoid presenting any UI. In the 2017 StrongPity2 variant, the main component `wmpsvn32.exe` is staged in `%temp%\lang_be29c9f3-83we` and persists via an HKCU `...\CurrentVersion\Run` value named *Help Manager*; other variants persist via services/scheduled tasks. The hidden-window property is what lets the persistent, autostarted component run every logon without the user noticing — so the hunt looks for the intersection of "runs hidden," "lives in a `%temp%`/language-named folder or bears a masqueraded name," and "is wired into an autostart mechanism."
- **Why a hunt, not a rule:** Hidden-window execution is one of the least specific properties available — a huge fraction of legitimate background/service processes have no window. A standalone alert on `WindowStyle Hidden` or on the ShowWindow/SW_HIDE flag would be pure noise. The signal only emerges when hidden-window execution is *joined* to anomalous path, masqueraded name, missing trust, and a persistence reference — a multi-source correlation and judgement task. Where a tighter, repeatable observable exists (the *Help Manager* Run value → `%temp%\lang_<hex>` payload path, or a service whose image sits in a `lang_*` folder), those are precise enough to hand to detection-engineering as scoped analytics — this hunt exists to *surface* such durable observables and the components that carry them, not to alert on hidden windows.

## Data sources required

- Process-creation telemetry with command line, window-style/creation flags, image path, parent lineage, and signature status (Sysmon Event ID 1 / EDR `DeviceProcessEvents`)
- Autostart telemetry: registry Run-key writes (Sysmon Event ID 13), service installs (Event ID 7045), scheduled-task creation (Event ID 4698) — to establish the persistence reference
- EDR file-write telemetry for `%temp%\lang_*` staging folders and dropped component names
- Code-signing/trust status per image (join to HUNT-03's untrusted-signer view)

## Query starting point

Platform: `EDR (Microsoft Defender Advanced Hunting / KQL)` — intersect hidden-window/background execution with a `%temp%`/masqueraded path AND an autostart reference

```kusto
// (a) Processes launched from %temp%/lang_* or bearing a known masqueraded component name, untrusted or unsigned
let suspectProc = DeviceProcessEvents
    | where TimeGenerated > ago(30d)
    | where FolderPath has_any ("\\Temp\\lang_","\\AppData\\","lang_")
        or FileName in~ ("wmpsvn32.exe","nvvscv.exe","procexp.exe","wndplyr.exe","prst.dll","wrlck.dll")
    | project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, SHA1;
// (b) Autostart references landing in the same folder / naming the same binary (persistence context)
let persistence = union
    ( DeviceRegistryEvents
      | where TimeGenerated > ago(30d)
      | where RegistryKey has @"\CurrentVersion\Run"
      | where RegistryValueData has_any ("\\Temp\\lang_","lang_") or RegistryValueName has "Help Manager"
      | project DeviceName, persistType = "RunKey", ref = RegistryValueData, name = RegistryValueName ),
    ( DeviceEvents
      | where TimeGenerated > ago(30d)
      | where ActionType in ("ServiceInstalled","ScheduledTaskCreated")
      | where AdditionalFields has_any ("\\Temp\\lang_","lang_","wmpsvn32","nvvscv","wndplyr")
      | project DeviceName, persistType = ActionType, ref = tostring(AdditionalFields), name = "" );
// The finding = a %temp%/masqueraded component that is ALSO wired into an autostart mechanism
suspectProc
| join kind=inner (persistence) on DeviceName
| where ref has_any (FolderPath, FileName) or FolderPath has "lang_"
| order by TimeGenerated desc
// Then confirm hidden-window/SW_HIDE creation flag on the process where the sensor exposes it, and untrusted signature (HUNT-03)
```

## Triage guidance

- **Likely malicious:** a background/hidden-window process running from `%temp%\lang_<hex>-<suffix>` (or a masqueraded name like `wmpsvn32.exe`/`nvvscv.exe`) that is unsigned/untrusted AND referenced by an HKCU *Help Manager* Run value, a service, or a scheduled task pointing back into that folder — the near-exact StrongPity2 signature. Corroborate with a Defender-exclusion add for the same directory (detection-pack T1685) and any prior trojanized-installer parent (HUNT-01/HUNT-02).
- **Likely benign / expected:** the overwhelming majority of hidden/no-window processes are legitimate services, updaters, and tray/background apps — never treat hidden-window alone as suspicious. Some installers stage helpers in `%temp%` transiently; the discriminator is *persistence into* a `%temp%`/language-named folder plus missing trust. Signed vendor background processes referenced by Run keys are normal.
- **Pivot next:** confirmed → this is an established StrongPity foothold; pull the component set (`prst.*`/`wrlck.*`, `.sft` staging), hand the durable *Help Manager → `%temp%\lang_*`* Run-value observable and the `lang_*`-image service/task to detection-engineering as scoped analytics, and escalate to incident-response-coordinator for host isolation and credential/collection scoping (detection-pack T1547.001/T1543.003/T1053.005/T1074.001/T1041).

## References

- https://www.welivesecurity.com/2017/12/08/strongpity-like-spyware-replaces-finfisher/
- https://attack.mitre.org/software/S0491/
- https://attack.mitre.org/techniques/T1564/003/
