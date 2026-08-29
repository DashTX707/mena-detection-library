# Hunt: Charming Kitten in-implant collection & low-telemetry discovery (keylog / screencap / sysinfo / connectivity)

- **Hypothesis:** If a NICECURL/TAMECAT/POWERSTAR implant is resident on a host, then rather than discrete tool events we should observe the *behavioral shadow* of its in-process collection and discovery — a long-lived script-host/backdoor process that periodically reaches out for an internet-connectivity check, queries OS/system info via WMI (`GetSystemCaption`-style OS-caption lookups), and exercises keyboard-hook and screen-capture APIs — activity that leaves little discrete telemetry and must be found by stacking behavioral anomalies on the same process.
- **ATT&CK:**
  - T1056.001 — Input Capture: Keylogging (credential-access)
  - T1113 — Screen Capture (collection)
  - T1082 — System Information Discovery (discovery)
  - T1016.001 — System Network Configuration Discovery: Internet Connection Discovery (discovery)

- **Actor procedure:** The implants profile and collect from inside their own process to minimize footprint. NICECURL gathers system information (its YARA rule references a `GetSystemCaption` function retrieving the OS caption); TAMECAT and the modular backdoors check for internet connectivity to confirm C2 reachability before beaconing; the actor captures screenshots and uses keylogging to harvest credentials and input — all via benign in-process APIs that emit almost no distinct events.
- **Why a hunt, not a rule:** These techniques are deliberately low-telemetry — user-mode keyboard hooks, GDI/`BitBlt` screen capture, WMI OS-caption queries and a lone connectivity probe each blend into ordinary application behavior and have huge benign base rates (every app checks connectivity; screen capture is what screenshot/RDP tools do). No single one is alertable. The only tractable approach is *behavioral, stacked*: attribute these primitives to a **suspicious long-lived script-host/unsigned process** that is *also* beaconing (HUNT-04) or was masquerade-delivered (HUNT-07). That correlation is analyst judgement over EDR behavioral telemetry — a hunt, and typically an IR-sweep once C2 is suspected.

## Data sources required

- EDR behavioral telemetry (API-level: `SetWindowsHookEx`/keyboard hooks, `BitBlt`/`GetDC` screen capture, injection)
- WMI-Activity operational log + Sysmon EID 1 (wmic/Get-CimInstance OS-caption queries)
- Sysmon EID 3 / EDR network (the connectivity-check + subsequent beacon on the same process)
- PowerShell script-block (EID 4104) for in-script sysinfo/screenshot/keylog logic

## Query starting point

Platform: `KQL / Microsoft Sentinel` (Defender for Endpoint) — stack sysinfo + connectivity-check + capture behaviors on a single suspicious process

```kusto
let suspectProcs = dynamic(["wscript.exe","cscript.exe","powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","conhost.exe","curl.exe"]);
// sysinfo / OS-caption discovery (T1082)
let sysinfo = DeviceProcessEvents
  | where ProcessCommandLine has_any ("Win32_OperatingSystem","os get caption","systeminfo","GetSystemCaption","ComputerSystem")
  | project DeviceName, t=TimeGenerated, sig="sysinfo", proc=InitiatingProcessFileName;
// internet-connectivity check (T1016.001)
let conncheck = DeviceNetworkEvents
  | where RemoteUrl has_any ("www.msftconnecttest.com","ipinfo.io","api.ipify.org","checkip","icanhazip.com")
        or RemoteUrl endswith "/generate_204"
  | where InitiatingProcessFileName in~ (suspectProcs)
  | project DeviceName, t=TimeGenerated, sig="conncheck", proc=InitiatingProcessFileName;
// keylog / screen-capture behavioral flags (T1056.001 / T1113) via EDR behavior events
let capture = DeviceEvents
  | where ActionType in ("SetWindowsHookExApiCall","GetAsyncKeyStateApiCall","ScreenshotTaken","BitBltApiCall")
  | where InitiatingProcessFileName in~ (suspectProcs)
  | project DeviceName, t=TimeGenerated, sig="capture", proc=InitiatingProcessFileName;
union sysinfo, conncheck, capture
| summarize sigs=make_set(sig), procs=make_set(proc), events=count(),
            window=max(t)-min(t) by DeviceName
| where array_length(sigs) >= 2          // stack >=2 behavioral primitives on the same host/process
| sort by array_length(sigs) desc, events desc
```

## Triage guidance

- **Likely malicious:** a single long-lived script-host/unsigned process on one host that stacks two-or-more of {OS-caption/sysinfo query, connectivity probe, keyboard-hook, screen-capture} AND is beaconing to glitch/tebi (HUNT-04) or was masquerade-delivered (HUNT-07); connectivity check immediately followed by the first C2 beacon from the same PID.
- **Likely benign / expected:** browsers/OS components doing NCSI connectivity checks; RDP/remote-support and screenshot tools doing legitimate capture; inventory/monitoring agents querying `Win32_OperatingSystem`; accessibility software using keyboard hooks. Each in isolation is normal — only the *stack on a suspicious process* matters. Baseline your monitoring/RMM agents and suppress.
- **Pivot next:** confirm the process image and parent chain, pull the loader for obfuscation constants (HUNT-06) and C2 config (HUNT-04/05), and scope keylog/screenshot output staging (7-Zip archives — detection pack T1560.001). A confirmed collecting implant is a live incident → escalate to IR immediately and sweep the estate.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
