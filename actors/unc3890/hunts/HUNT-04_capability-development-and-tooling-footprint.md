# Hunt: UNC3890 — custom-malware development & public-tooling footprint (SUGARUSH/SUGARDUMP, Metasploit/Unicorn/NorthStar)

- **Hypothesis:** The development and acquisition of UNC3890's capabilities happen off-victim, so they are un-alertable — but if the actor is *present*, the developed/obtained tooling leaves a distinctive downstream footprint that a hunt can surface even when the network IOCs have rotated. Specifically: (1) the **custom malware family's durable artifacts** — the SUGARUSH `Service1` service + `Logs`/`ServiceLog` folders + port-4585 reverse shell, and SUGARDUMP's Farsi build fingerprints (PDB paths `passrecover.pdb` / `ChromeRecovery.pdb`, .NET project name `yaal`, the AES password string containing `KHODA`); and (2) the **public-tooling behavioral tells** — Unicorn's PowerShell downgrade+shellcode-injection pattern, Metasploit stager shellcode, and a NorthStar C2 stager (MD5 2fe42c52826787e24ea81c17303484f9) beaconing to 143.110.155.195. The hypothesis assumes compromise and asks: *if the tooling ran here, where is the residue*, hunting the implementation-core artifacts the actor can't change without re-engineering the malware, not the IPs they change nightly.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — UNC3890 authored SUGARUSH and multiple SUGARDUMP versions with Farsi build artifacts (`yaal`, `KHODA`, `passrecover.pdb`); the hunt looks for those durable implementation fingerprints and the malware's on-host residue.
  - T1588.002 — Obtain Capabilities: Tool (resource-development) — UNC3890 operationalized Metasploit, Unicorn (PowerShell downgrade/shellcode) and NorthStar C2; the hunt looks for those tools' behavioral/stager footprints downstream.

- **Actor procedure:** UNC3890 developed proprietary malware — SUGARUSH (small first-stage backdoor: creates a Windows service `Service1`, opens a reverse TCP shell to a hardcoded C2 on port 4585, runs CMD commands) and SUGARDUMP (browser-credential stealer, iterating through a local-file version in 2021, an SMTP-exfil version in late 2021/early 2022, and an HTTP-exfil version in April 2022). SUGARDUMP carried Farsi-language dev artifacts: the .NET project name `yaal` (Farsi for a horse's mane) and an AES password string containing `KHODA` (Farsi for "God"), plus PDB paths `passrecover.pdb` / `ChromeRecovery.pdb`. Alongside the custom code, UNC3890 obtained and used public offensive tooling — the Metasploit framework, Unicorn (PowerShell downgrade + shellcode injection generator), and the open-source NorthStar C2 framework (stager MD5 2fe42c52826787e24ea81c17303484f9, C2 143.110.155.195).
- **Why a hunt, not a rule:** Development and tool acquisition are pure off-victim resource-development — there is no victim telemetry to alert on for the *act* itself. What is on-victim is generic (a Windows service, a PowerShell process, a beacon) and blends with administration and red-team activity, so a naive rule floods with false positives; and the network IOCs (MD5 hash, C2 IP) are Summiting Level 1 indicators the actor rotates freely. The hunt's value is anchoring on the *high-level, hard-to-change* residue — the Farsi PDB/project-name/password strings baked into the compiled malware (implementation-core, Summiting Level 4), and the tools' *behavioral* patterns (Unicorn's downgrade+inject cradle, NorthStar's stager staging) — and correlating them across YARA memory/file scans, script-block logs and service telemetry. That cross-source judgement is hunt work; if a durable artifact proves crisp (e.g., the `Service1`+port-4585 pair), it belongs in the detection lane (it already is — T1543.003/T1571), not re-litigated here.

## Data sources required

- EDR file + memory telemetry, and on-demand YARA/string scanning across endpoints (for the SUGARDUMP build strings and `Service1`/`Logs`/`ServiceLog` residue)
- Windows service-install telemetry (Event ID 7045) and Sysmon process-create (parent=services.exe) — SUGARUSH service footprint
- PowerShell script-block + module logging (Event ID 4104) — Unicorn downgrade/shellcode-injection cradles, Metasploit stager one-liners
- Netflow/proxy to the tooling C2s (143.110.155.195 NorthStar, 161.35.123.176 SUGARUSH) and file-hash telemetry for the NorthStar stager MD5
- Threat-intel hash watchlist (the Mandiant MD5 appendix) as a pivot, not the basis

## Query starting point

Platform: `EDR (Microsoft Defender advanced hunting / KQL)` — hunt the durable malware build strings and tooling residue, not the rotating IOCs

```kusto
// (a) SUGARDUMP durable build fingerprints in files/memory (implementation-core, Summiting L4)
union DeviceFileEvents, DeviceImageLoadEvents
| where TimeGenerated > ago(30d)
| where FileName endswith ".exe" or FileName endswith ".dll"
| where InitiatingProcessCommandLine has_any ("yaal","KHODA","passrecover.pdb","ChromeRecovery.pdb")
      or FileName in~ ("CrashReporter.exe","3-Video-VLC.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName
// (b) SUGARUSH service residue: a Service1 install whose binary sits in a user/temp path
| union (
    DeviceEvents
    | where TimeGenerated > ago(30d) and ActionType == "ServiceInstalled"
    | extend svc = tostring(parse_json(AdditionalFields).ServiceName)
    | where svc =~ "Service1" or AdditionalFields has_any ("ServiceLog","\\Logs\\")
    | project TimeGenerated, DeviceName, svc, AdditionalFields )
// (c) Unicorn / Metasploit PowerShell cradle tells
| union (
    DeviceProcessEvents
    | where TimeGenerated > ago(30d) and FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("-version 2","-Version 2.0","FromBase64String",
             "System.Net.Sockets.TCPClient","IEX (New-Object Net.WebClient)","-enc ")
    | project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName )
```

## Triage guidance

- **Likely malicious:** any file/process carrying the SUGARDUMP build strings (`yaal`, `KHODA`, `passrecover.pdb`, `ChromeRecovery.pdb`) — these are near-unique to the actor; a `Service1` install pointing at a binary in a user/temp path with `Logs`/`ServiceLog` folders alongside; a PowerShell process forcing a v2 downgrade *and* opening a raw TCPClient socket (the Unicorn/reverse-shell pattern); a NorthStar stager hash or beacon to 143.110.155.195. The build strings are the strongest single tell because the actor cannot change them without re-authoring the malware.
- **Likely benign / expected:** legitimate services genuinely named in ways that collide with `Service1` (rare, but confirm the binary path and signer); red-team/pentest engagements running Metasploit, Unicorn or NorthStar — deconflict with the offensive-security team before escalating; developers and admins using Base64/`-enc` PowerShell and `TCPClient` for legitimate automation — baseline the known scripts and signers; PowerShell v2 present for genuine legacy-app compatibility. Generic PowerShell or a lone hash-miss with no build-string or service corroboration is thin.
- **Pivot next:** a build-string or `Service1`+port-4585 hit is a confirmed SUGARUSH/SUGARDUMP infection — escalate to incident-response-coordinator, isolate the host, and pivot to the full detection pack (T1543.003, T1571, T1555.003, T1048/T1041) and to HUNT-05 for the host-profiling context. Preserve the sample and its Farsi artifacts as attribution intel. Deconfirmed red-team hits: document the deconfliction and tune the baseline so the pattern still surfaces a real actor.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping
- https://www.securityweek.com/iranian-group-targeting-israeli-shipping-and-other-key-sectors/
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1588/002/
