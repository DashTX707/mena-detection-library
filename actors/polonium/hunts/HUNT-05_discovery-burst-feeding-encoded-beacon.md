# Hunt: POLONIUM — recon discovery burst feeding the Base64-encoded beacon

- **Hypothesis:** Each POLONIUM discovery command is individually trivial and ubiquitous, but the actor runs them as a *tight burst right after foothold* and folds the results (username, IP, host info) into the **Base64-encoded C2 beacon**. If the group is here, the tell is a *sequenced recon cluster* — file/dir enumeration, process listing, system-info, network-config and whoami — emitted by a single non-shell parent process (an implant, InstallUtil, or PowerShell) within a short window, *followed by* an outbound web request carrying Base64-encoded username/IP tokens. Any one discovery command is noise; the burst-plus-encoded-egress on one process lineage is the finding.
- **ATT&CK:**
  - T1083 — File and Directory Discovery (discovery) — enumerating documents/data of interest for collection; hunt as part of the post-foothold burst.
  - T1057 — Process Discovery (discovery) — enumerating running processes for environment recon.
  - T1082 — System Information Discovery (discovery) — OS/machine identifiers Base64-encoded into the beacon.
  - T1016 — System Network Configuration Discovery (discovery) — host IP read and Base64-encoded into outbound requests.
  - T1033 — System Owner/User Discovery (discovery) — logged-in username Base64-encoded into C2 request URIs.

- **Actor procedure:** POLONIUM's implants enumerate **files/directories** (locate data of interest), **processes** (environment recon), **system information** (OS, machine ID) and **network configuration** (host IP), and query the **current username** — then **Base64-encode the username and IP** into outbound web-request URIs to identify and track the victim. The distinguishing signal is not the discovery itself but that the recon output *becomes the encoded beacon*: the discovery burst and the encoded egress are two ends of the same behavior, launched from one implant lineage.
- **Why a hunt, not a rule:** `whoami`, `ipconfig`, `tasklist`, `systeminfo` and directory listing run thousands of times a day across any estate — logon scripts, admin sessions, software inventory all generate them, so a rule on any single command is unusable. The finding requires correlating a *cluster* of distinct discovery techniques from one non-interactive parent in a short window, then linking it to an outbound request bearing Base64 username/IP tokens — a sequence/lineage correlation that is analyst work. If the encoded-URI half proves crisp on its own (a proxy regex for `?u=<base64user>&ip=<base64ip>` to IP-only C2 — a Level-2/3 observable), hand that to detection-engineering.

## Data sources required

- EDR / Sysmon process-creation (EID 1) with full command line and parent-process lineage
- PowerShell script-block logging for discovery cmdlets issued in-script
- Proxy / web-gateway logs with full request URIs (for Base64 username/IP token detection) and NetFlow for IP-only C2 egress
- Host asset context (which parent processes are legitimate inventory agents vs unknown implants)

## Query starting point

Platform: `Splunk SPL (EDR process events + proxy)`

```spl
index=edr EventCode=1
| eval disc=case(
    match(process,"(?i)whoami|net user|query user"), "T1033",
    match(process,"(?i)ipconfig|netsh|route print|arp -a|getmac"), "T1016",
    match(process,"(?i)systeminfo|wmic os|ver$"), "T1082",
    match(process,"(?i)tasklist|get-process|wmic process"), "T1057",
    match(process,"(?i)dir /s|Get-ChildItem|tree |where /r"), "T1083",
    1==1, null())
| where isnotnull(disc)
| bin _time span=10m
| stats dc(disc) as tech_types values(disc) as techniques values(process) as cmds
        by _time host parent_process parent_process_guid
| where tech_types >= 3                       // burst = 3+ distinct discovery techniques from one parent
| where NOT match(parent_process,"(?i)ccmexec|SenseIR|inventory|gpscript|explorer\.exe")
| join type=left host
    [ search index=proxy (uri="*?*" AND (uri="*u=*" OR uri="*ip=*"))
      | regex uri="[A-Za-z0-9+/]{12,}={0,2}"    // base64-looking token
      | where match(dest,"^\d+\.\d+\.\d+\.\d+$") // IP-only destination
      | stats values(uri) as beacon_uris values(dest) as c2 by host ]
| eval score = tech_types + if(isnotnull(beacon_uris),5,0)
| sort - score
```

## Triage guidance

- **Likely malicious:** 3+ distinct discovery techniques fired within minutes from a single non-inventory parent (an unknown .NET binary, InstallUtil, or PowerShell implant), *followed by* an outbound request to an IP-only host on a non-standard port carrying a Base64-looking username/IP token; a recon burst on a host that also shows cloud-C2 (HUNT-03) or masqueraded binaries.
- **Likely benign / expected:** software-inventory and endpoint-management agents (SCCM/CcmExec, Defender SenseIR, asset scanners) that legitimately run the full discovery set on a schedule — baseline and exclude those parents; admin troubleshooting sessions from `explorer.exe`/interactive shells; logon scripts. The burst alone from a *known* inventory parent is expected — from an *unknown* parent with an encoded beacon it is not.
- **Pivot next:** identify and hash the parent process; if unknown/unsigned, treat as the implant and pivot to its cloud-C2 (HUNT-03), persistence (detection pack T1053.005/T1547.009) and collection/staging (HUNT-06). Decode the beacon token to confirm it carries this host's username/IP. A confirmed encoded beacon to IP-only C2 is a live implant — escalate to incident-response-coordinator.

## References

- https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/
- https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1057/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1016/
- https://attack.mitre.org/techniques/T1033/
