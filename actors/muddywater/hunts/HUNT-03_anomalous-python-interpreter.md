# Hunt: Anomalous Python / non-native interpreter on Windows endpoints

- **Hypothesis:** If MuddyWater deployed a Python-based tool (e.g. Out1) on a Windows endpoint that is not a developer/data-science workstation, then we should observe a Python interpreter (`python.exe`, `pythonw.exe`, or a PyInstaller-frozen EXE) executing from a user-writable/temp path with network activity — a never-before-seen binary/interpreter on that host class.
- **ATT&CK:**
  - T1059.006 — Command and Scripting Interpreter: Python (execution)
- **Actor procedure:** MuddyWater has developed tooling in **Python, including Out1**, used for data manipulation and follow-on tasking.
- **Why a hunt, not a rule:** Python is legitimate and widespread on developer, DevOps and analytics hosts, so a blanket alert would drown any SOC. But on the *typical corporate endpoint* (finance, gov, telecom back-office — MuddyWater's targets) a Python interpreter is a strong never-before-seen anomaly. Distinguishing the two requires knowing each host's role, i.e. baselining — a hunt, not a fixed rule.

## Data sources required

- Sysmon EID 1 / Security 4688 (process creation, image path, hashes)
- Sysmon EID 3 (network connection) to correlate interpreter → outbound
- Asset inventory / host-role tags (to separate dev hosts from standard endpoints)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=1 OR EventCode=4688)
| eval img=lower(coalesce(Image, New_Process_Name))
| where match(img,"python(w)?\.exe$") OR match(img,"py\.exe$")
| eval userland=if(match(img,"(appdata|\\temp\\|\\users\\public|\\programdata\\|\\downloads\\)"),1,0)
| stats count values(img) as image values(CommandLine) as cmd
        values(ParentImage) as parent min(_time) as first_seen by host
| lookup asset_roles host OUTPUT role
| where role!="developer" AND role!="devops" AND role!="analytics"
| sort first_seen
```

## Triage guidance

- **Likely malicious:** Python interpreter or frozen EXE running from `%temp%`/`%appdata%`/Downloads on a non-developer host; parent is a script interpreter, Office app, or RMM agent; immediate outbound connections after launch; first-ever appearance on that host.
- **Likely benign / expected:** Developer/DevOps/analytics workstations; vendor agents that bundle Python (some backup, security and monitoring products embed it — enumerate and baseline these); Python installed under `Program Files`/official install path with a valid signature.
- **Pivot next:** Hash reputation and module imports (socket/requests → C2); outbound destinations (→ HUNT-05); how the interpreter arrived (ingress transfer — detection lane).

## References

- https://attack.mitre.org/groups/G0069/
