# Hunt: Agrius lateral tool transfer — follow-on payloads pulled from consumer file-sharing sites and pushed between internal hosts

- **Hypothesis:** If Agrius is arming hosts for the next stage, then we should observe follow-on tooling arriving from legitimate consumer file-sharing services (observed `ufile.io`, `easyupload.io`) — a server or workstation reaching out to a personal file-share domain and, shortly after, a new executable written to a user-writable path and executed — and/or tooling being copied host-to-host over SMB admin shares (`\\host\C$\...`) followed by execution on the destination, standing out from normal software distribution which flows from sanctioned repositories and management servers.
- **ATT&CK:**
  - T1570 — Lateral Tool Transfer (lateral-movement) — download from ufile.io/easyupload.io and internal SMB tool copies
- **Actor procedure:** Agrius downloaded follow-on payloads for execution from legitimate file-sharing services such as `ufile.io` and `easyupload.io`, and moved tooling (scanners, Mimikatz, ProcDump, Plink/pscp, wipers, driver loaders) between hosts inside victim networks. Using consumer file-share sites rides a trusted, TLS-encrypted channel that is rarely blocked and blends with employee behavior; internal SMB copies ride trusted admin channels — both evade signature detection tuned to known-bad download infrastructure.
- **Why a hunt, not a rule:** consumer file-sharing is used legitimately by employees every day, and SMB file copies between hosts are the backbone of normal software distribution and admin work. Blocking or alerting on all of it is infeasible. The durable signal (Summiting Level 3, technique behavior) is the *lineage*: a file-share download or SMB write that lands an executable in a non-standard path (`%temp%`, `%public%`, `\windows\temp\`) which then executes — especially on servers, which should not be pulling files from personal file-shares at all. That requires baselining who legitimately uses these services and how software normally reaches a host.

## Data sources required

- Web proxy / DNS / TLS-SNI logs — connections to `ufile.io`, `easyupload.io`, and the file-sharing/upload proxy category, with requesting host and user
- Sysmon EID 11 (file create) + EID 15 (file-create stream/MOTW) — executables written by browsers, or to `%temp%`/`%public%`/`\windows\temp\`
- Sysmon EID 1 / 4688 — execution of the freshly-written file (parent = browser or a remote-created process)
- Windows Security 5145 (network share object access) / SMB audit — remote writes to `C$`/`ADMIN$` admin shares

## Query starting point

Platform: `KQL / Microsoft Sentinel`

```
// A: consumer file-share download that lands and runs an executable
let fileshare = dynamic(["ufile.io","easyupload.io","anonfiles","gofile.io","dropmefiles"]);
let dl =
    DeviceNetworkEvents
    | where RemoteUrl has_any (fileshare) or todynamic(RemoteUrl) has_any (fileshare)
    | project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName;
let newexe =
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FolderPath has_any (@"\temp\", @"\appdata\", @"\public\", @"\windows\temp\")
    | where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".sys"
    | project fcTime=TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName;
dl
| join kind=inner newexe on DeviceName
| where fcTime between (TimeGenerated .. TimeGenerated + 15m)
| project TimeGenerated, DeviceName, RemoteUrl, FileName, FolderPath, dropper=newexe.InitiatingProcessFileName
```
Companion (B): hunt `DeviceFileEvents` where `ActionType == "FileCreated"` and `FolderPath` starts with a
remote admin-share path, joined to a subsequent process create of that file — internal SMB tool push.

## Triage guidance

- **Likely malicious:** any *server* (esp. internet-facing/DB) downloading from `ufile.io`/`easyupload.io`; a consumer file-share fetch immediately followed by an `.exe`/`.sys` write to `%temp%`/`\windows\temp\` and execution; a renamed system-looking binary (`systems.exe`, `AGMT.sys`) arriving this way; an executable written to `C$`/`ADMIN$` from a host that is not a management server, then run. Correlate against the renamed-tool masquerading tells in HUNT-04.
- **Likely benign / expected:** employees using file-sharing sites for legitimate document exchange; software distributed from sanctioned SCCM/Intune/repo servers over SMB; admin scripts copied by known management accounts. Baseline sanctioned distribution servers and normal file-share users.
- **Pivot next:** identify the tool that landed and map it to the chain — scanner (HUNT-02), credential-dumper (detection lane), Plink/pscp (exfil, detection lane), or a wiper/driver loader (HUNT-04/06). Walk back to how the downloading host was first accessed (HUNT-05). Tool transfer to multiple hosts in short order signals imminent broad action — escalate if wiper/BYOVD tooling is identified.

## References

- https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/
- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://attack.mitre.org/groups/G1030/
