# Hunt: Exfiltration to cloud storage (Rclone/Wasabi) & archive staging

- **Hypothesis:** If MuddyWater is exfiltrating from this environment, then we should observe collected data being archived with a native utility (`makecab.exe` outside a servicing context) and/or moved out via `Rclone` to a cloud-storage endpoint such as **Wasabi** — a staging-then-push sequence on a single host, distinct from routine backup traffic.
- **ATT&CK:**
  - T1560.001 — Archive Collected Data: Archive via Utility (collection)
  - T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage (exfiltration)
- **Actor procedure:** MuddyWater has used the native Windows cabinet tool **`makecab.exe`** (likely to compress stolen data) and attempted to **exfiltrate to Wasabi cloud storage using `Rclone`**.
- **Why a hunt, not a rule:** `makecab.exe` runs legitimately during Windows servicing/CBS operations, and cloud-storage traffic is normal in most orgs. Rclone can be renamed and its traffic is TLS. The malicious signal is the *sequence and context* (archive of user/document data by an unusual parent, followed by an outbound push to a storage provider with no business relationship) plus process-argument fingerprints — which needs baselining of legitimate backup/servicing behavior.

## Data sources required

- Sysmon EID 1 / Security 4688 (process + full command line for `makecab.exe`, rclone-like binaries)
- Sysmon EID 3 / proxy / firewall (outbound to Wasabi `*.wasabisys.com` and other object-storage endpoints)
- Sysmon EID 11 (creation of `.cab`/`.zip`/`.7z` archives in user/temp paths)

## Query starting point

Platform: `KQL/Sentinel`

```kql
// A. archive staging by an unusual parent (makecab outside servicing)
let stage = DeviceProcessEvents
| where FileName in~ ("makecab.exe","rar.exe","7z.exe","7za.exe") 
     or ProcessCommandLine has_any ("makecab","-recurse","a -hp","cab /d")
| where InitiatingProcessFileName !in~ ("TiWorker.exe","TrustedInstaller.exe","dism.exe","CompatTelRunner.exe")
| project StageTime=TimeGenerated, DeviceName, AccountName, FileName,
          InitiatingProcessFileName, ProcessCommandLine;
// B. rclone-like process OR outbound to cloud object-storage
let push = union
  (DeviceProcessEvents
    | where ProcessCommandLine has_any ("rclone","copy ","sync ","--config","obscure") 
        and ProcessCommandLine has_any ("wasabi","s3","b2:","mega:","remote:")
    | project PushTime=TimeGenerated, DeviceName, ProcessCommandLine),
  (DeviceNetworkEvents
    | where RemoteUrl has_any ("wasabisys.com","s3.amazonaws.com","backblazeb2.com","mega.nz")
    | project PushTime=TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName);
stage
| join kind=inner push on DeviceName
| where PushTime between (StageTime .. StageTime + 2h)
```

## Triage guidance

- **Likely malicious:** `makecab`/archive of user documents or collection folders by `powershell.exe`/`cmd.exe`/RMM parent (not TrustedInstaller/DISM); any `rclone`-style command with `wasabi`/`s3` remotes and `obscure`d credentials; outbound to Wasabi from a host with no sanctioned Wasabi account; archive → push within a couple of hours.
- **Likely benign / expected:** `makecab.exe` under `TiWorker.exe`/`TrustedInstaller.exe` (Windows servicing) and CBS log packaging; sanctioned backup/DR tools pushing to approved object storage; developers using S3 legitimately. Baseline approved storage tenants and backup agents.
- **Pivot next:** Enumerate what was archived (file paths in command line); correlate with beaconing (→ HUNT-05) and credential theft (→ HUNT-08); if confirmed data movement to unsanctioned storage, **escalate to incident-response** — this is likely live exfiltration.

## References

- https://attack.mitre.org/groups/G0069/
