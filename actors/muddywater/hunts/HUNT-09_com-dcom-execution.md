# Hunt: COM / DCOM / Outlook object execution

- **Hypothesis:** If MuddyWater is using COM/DCOM/Outlook object model for code execution, then we should observe anomalous COM-server instantiation or DCOM activation producing child processes on hosts — e.g. Outlook or a scripting host brokering execution — that does not match normal application behavior.
- **ATT&CK:**
  - T1559.001 — Inter-Process Communication: Component Object Model (execution)
- **Actor procedure:** MuddyWater has used malware capable of **executing malicious code via COM, DCOM, and Outlook**.
- **Why a hunt, not a rule:** COM/DCOM is the backbone of legitimate Windows IPC — Office automation, WMI, admin tooling all use it constantly, and it is poorly instrumented by default. There is no clean signature; the hunt keys on unexpected process-lineage relationships (e.g. Outlook or `dllhost.exe`/`svchost.exe` COM surrogate spawning a script/LOLBin child) that need heavy baselining.

## Data sources required

- Sysmon EID 1 (process create; watch `ParentImage` = `outlook.exe`, `dllhost.exe /Processid:{CLSID}`, `mmc.exe`)
- Sysmon EID 7 (image load into COM surrogate hosts)
- Windows Security 4688; DCOM/RPC event logs where available

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (EventCode=1 OR EventCode=4688)
| eval parent=lower(coalesce(ParentImage,Parent_Process_Name))
| eval child=lower(coalesce(Image,New_Process_Name))
| eval cmd=lower(coalesce(CommandLine,Process_Command_Line))
| where (parent="outlook.exe" AND match(child,"(powershell|cmd|wscript|cscript|mshta|rundll32)\.exe"))
     OR (match(parent,"dllhost\.exe") AND like(cmd,"%/processid:{%") )
     OR (parent="dllhost.exe" AND match(child,"(powershell|cmd|wscript|mshta)\.exe"))
| stats count values(cmd) as cmds values(child) as children by host, user, parent
| sort - count
```

## Triage guidance

- **Likely malicious:** `outlook.exe` spawning `powershell.exe`/`mshta.exe`/`wscript.exe` (Outlook object-model abuse); a DCOM surrogate (`dllhost.exe /Processid:{CLSID}`) launching a script interpreter; COM activation of a rarely-used CLSID producing a LOLBin child; activity correlated with inbound internal phishing (→ HUNT-14).
- **Likely benign / expected:** Office add-ins, mail-merge and automation macros used by the business; legitimate admin/COM automation; some AV/backup products that use COM surrogates. Baseline the CLSIDs and parent→child pairs that are normal in the estate.
- **Pivot next:** Trace the child process forward (discovery/C2); check for DDE-based execution and macro persistence on the same host; identify the triggering mail item if Outlook is the parent.

## References

- https://attack.mitre.org/groups/G0069/
