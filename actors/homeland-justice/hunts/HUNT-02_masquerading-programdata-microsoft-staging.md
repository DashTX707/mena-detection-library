# Hunt: Homeland Justice masqueraded payload staging in ProgramData\Microsoft (unsigned binaries in Microsoft-looking paths)

- **Hypothesis:** If Storm-0842 staged its destructive tooling to blend with the OS, then across the fleet we should find **unsigned or unknown-reputation executables masquerading inside Microsoft-branded system paths** — chiefly `C:\ProgramData\Microsoft\Windows\` (where `GoXml.exe` was staged) and sibling `C:\ProgramData\Microsoft\*` / `C:\Windows\*` directories — where a legitimate Windows binary of that name/location would be Microsoft-signed. This is a data-based sweep: enumerate every PE under Microsoft-looking paths, subtract signed/known-good, and surface the never-before-seen residue. A binary named to look systemic but *unsigned and low-prevalence* is the anomaly, independent of any specific hash (which expires).
- **ATT&CK:**
  - T1036 — Masquerading (defense evasion / "stealth") — path-and-property mismatch, not a name/hash match

- **Actor procedure:** Per AA22-264A the ROADSWEEP payload was staged as `GoXml.exe` under `C:\ProgramData\Microsoft\Windows\`, deliberately placing an unsigned destructive binary in a Microsoft-looking directory so it would blend with legitimate system content and evade name-based review. Companion tooling (`cl.exe`, `win.bat`, `bb.bat`, `disable_defender.exe`) was likewise dropped to disk during staging. The path is the masquerade — the directory implies "Microsoft," the file's signature and reputation do not.
- **Why a hunt, not a rule:** Name-and-path masquerading is LOW detection-feasibility because a rule keyed on the string `GoXml.exe` or a known hash is trivially defeated — the next operation renames the binary and the path is reused by legitimate software (many vendors and Microsoft components legitimately write to `C:\ProgramData\Microsoft\`). A blanket "unsigned EXE in ProgramData" alert has an unworkable base rate (installers, updaters, and LOB apps drop unsigned helpers there constantly). The discriminating work is *reputation + prevalence + property-mismatch* reasoning over the fleet's own baseline: an executable whose location implies a trusted publisher but whose signature/prevalence contradicts it, that no other host has, that appeared recently. That triage judgement is hunt-grade. The durable core (Summiting Level 3-4): *an unsigned, fleet-unique PE written to a Microsoft-branded system path* — a candidate to hand to detection-engineering as a low-volume enrichment/hunt-feed once the signed-path allowlist is built, not a blind alert.

## Data sources required

- EDR file inventory / DeviceFileEvents (FileCreated) — PE writes under `C:\ProgramData\Microsoft\*`, `C:\Windows\*`, `C:\ProgramData\*`
- Authenticode signature status + Microsoft-publisher check per file (signed / unsigned / signer)
- Fleet prevalence (dcount hosts per SHA256) + first-seen timestamp
- Sysmon EID 1 execution to confirm whether the staged binary has run (parent = cmd.exe/win.bat)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — unsigned, low-prevalence PEs in Microsoft-looking paths

```kusto
DeviceFileEvents
| where Timestamp > ago(90d)
| where ActionType == "FileCreated"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".sys"
| where FolderPath has @"\ProgramData\Microsoft\" or FolderPath startswith @"C:\Windows\"
        or FolderPath has @"\ProgramData\"
// join signature/publisher enrichment
| extend Signed = tostring(parse_json(AdditionalFields).IsSigned),
         Signer = tostring(parse_json(AdditionalFields).Signer)
| where Signed == "false" or Signer !has "Microsoft"          // property mismatch vs path
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 20),
            firstSeen = min(Timestamp), paths = make_set(FolderPath, 10)
        by FileName, SHA256, Signer, Signed
| where hosts <= 3                                            // fleet-rare = never-before-seen residue
| order by firstSeen desc
// Pivot: did it execute? DeviceProcessEvents | where SHA256 == "<hit>"
//   and InitiatingProcessFileName in~ ("cmd.exe","win.bat") — staged AND launched
```

## Triage guidance

- **Likely malicious:** an unsigned or non-Microsoft-signed executable that is unique-to-one-host (or a small cluster) sitting in `C:\ProgramData\Microsoft\Windows\` or another Microsoft-branded path, especially one named to evoke a system/office component (e.g. `GoXml.exe`, generic 2-3 letter names, or an office-doc-styled name); appeared recently; and — strongest — one that has *executed* with a `cmd.exe`/batch parent. Stack with HUNT-01 (does it enumerate-then-modify?) and detection-pack T1685 (is it `disable_defender.exe`-like?).
- **Likely benign / expected:** legitimate vendor updaters, telemetry helpers, and Microsoft components drop unsigned or self-signed helper binaries under `ProgramData\Microsoft\` on many hosts — high fleet prevalence + a coherent parent installer + a plausible vendor signer is the benign signature. Allowlist recurring known-good binaries by hash/signer once explained. A file seen on hundreds of hosts is not the residue you want.
- **Pivot next:** confirmed masqueraded staging binary → submit hash for reputation, pivot to HUNT-01 (execution/enumeration behavior) and to how it landed (web shell drop, admin-share copy, RDP session — detection-pack T1505.003/T1570/T1021). If the binary matches a known ROADSWEEP/No-Justice hash or shows destructive behavior, treat as pre-detonation staging and escalate to IR. Record explained-benign binaries to the hunting-wiki baseline to stop re-flagging.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a
- https://attack.mitre.org/techniques/T1036/
