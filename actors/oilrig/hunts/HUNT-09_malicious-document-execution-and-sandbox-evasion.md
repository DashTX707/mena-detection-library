# Hunt: OilRig macro/script execution & sandbox evasion (mouse/peripheral checks)

- **Hypothesis:** If OilRig lured a user into a macro-enabled document, then before dropping a payload the macro will run *environment checks* (is a mouse connected / peripheral present) to evade sandboxes, then hand off to a generic scripting interpreter — so hosts that executed the payload will show the interpreter lineage, while sandbox detonations will show the check but *no* follow-on, and the delta between them is itself the signal.
- **ATT&CK:**
  - T1059 — Command and Scripting Interpreter (execution)
  - T1497.001 — Virtualization/Sandbox Evasion: System Checks (defense-evasion)
  - T1120 — Peripheral Device Discovery (discovery)
- **Actor procedure:** OilRig **uses macros that verify whether a mouse is connected** (and identifies attached peripherals) to distinguish real users from analysis sandboxes, then **uses various scripting interpreters for execution** once the check passes.
- **Why a hunt, not a rule:** the mouse/peripheral check runs pre-payload inside the macro with almost no host log signal, and the generic `T1059` parent is too broad to alert on. The value is in macro static analysis plus correlating Office→script-host lineage against the population of documents that ran the check — analyst work and baselining, with the specific interpreter sub-techniques (PowerShell/VBS/cmd) already handed to the detection lane.

## Data sources required

- Office VBA macro extraction / mail-gateway detonation output (look for `GetSystemMetrics(SM_MOUSEPRESENT)`, `GetCursorPos`, WMI `Win32_PointingDevice` queries)
- Sysmon EID 1 / 4688 (Office → `wscript.exe`/`cscript.exe`/`powershell.exe`/`cmd.exe`/`mshta.exe` lineage)
- PowerShell 4104 script-block logging

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source=*Sysmon* EventCode=1) OR (source=WinEventLog:Security EventCode=4688)
| eval parent=lower(ParentImage), img=lower(Image), cmd=lower(coalesce(CommandLine,Process_Command_Line))
| where match(parent,"(winword|excel|powerpnt|outlook)\.exe$")
| eval interp=case(
    match(img,"(powershell|pwsh)\.exe$"),"powershell",
    match(img,"(wscript|cscript)\.exe$"),"vbs",
    match(img,"cmd\.exe$"),"cmd",
    match(img,"mshta\.exe$"),"mshta",
    match(img,"hh\.exe$"),"chm",
    1=1,null())
| where isnotnull(interp)
| eval sandbox_check=if(match(cmd,"(mousepresent|getcursorpos|win32_pointingdevice|sm_mouse)"),1,0)
| stats values(interp) as interpreters values(cmd) as cmds max(sandbox_check) as saw_check count by host, user, parent
| sort - count
```

## Triage guidance

- **Likely malicious:** an Office app spawning `wscript`/`powershell`/`mshta`/`hh.exe` shortly after document open, especially with an encoded command line; any macro artifact that queries mouse/pointing-device presence; the *same* lure hash that detonated inertly in the sandbox now spawning a payload on a real workstation.
- **Likely benign / expected:** legitimate business macros that call scripting for automation (enumerate and allowlist by document/template); developer scripting. Baseline Office→child lineage per department.
- **Pivot next:** feed the interpreter command line to the discovery-burst (HUNT-03) and C2 (HUNT-01) hunts; extract and detonate the parent document; hand the confirmed Office→script lineage to detection-engineering (it already owns the sub-technique rules).

## References

- https://attack.mitre.org/groups/G0049/
