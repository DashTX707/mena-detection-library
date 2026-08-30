# Hunt: Scarred-Manticore → Void Manticore handoff — Domain-Admin-driven manual data destruction (flagship)

- **Hypothesis:** If Void Manticore (Storm-0842) has been handed a victim by its espionage partner Scarred Manticore (Storm-0861), then the destructive phase begins with a **handed-off Domain Admin credential used from an unusual host** — typically the internet-facing web server carrying the web shell — followed by RDP into interior hosts and **hands-on-keyboard destruction with built-in utilities** (Windows Explorer bulk deletion, SysInternals SDelete, Windows Format Quick/Full), terminating in an abnormal crash/reboot. The hunt keys on the *chain* — a Domain Admin logon whose source host has never legitimately sourced admin auth, standing up an unexpected relationship between the account, the web server, and a burst of destructive file operations on a server that then reboots and fails to return — because no single link in that chain is malicious on its own.
- **ATT&CK:**
  - T1078.002 — Valid Accounts: Domain Accounts (initial-access) — DA credential handed off, first used from the web server; `do.exe` validates hard-coded DA creds
  - T1485 — Data Destruction (impact) — manual deletion via File Explorer, SDelete secure-wipe, Windows Format (Quick corrupts partition / Full destroys content)
  - T1529 — System Shutdown/Reboot (impact) — terminal BSOD / boot failure after destruction, rendering the endpoint inoperable

- **Actor procedure:** Per Check Point, one of Void Manticore's first actions after the transfer was use of a Domain Admin account it did not obtain itself. The bespoke `do.exe` carried hard-coded DA credentials, validated them, then dropped a further (reGeorge) web shell. The operator then moved by RDP using that DA access and destroyed data by hand — File Explorer deletion, `sdelete`, and the Windows Format utility — in addition to automated wipers. The affected systems then crash and fail to reboot.
- **Why a hunt, not a rule:** Every element here is individually indistinguishable from legitimate administration: Domain Admins log on, admins RDP, admins delete files and format volumes, and servers reboot. A rule on any one produces unmanageable noise. The malicious signal is *relational and sequenced* — a DA account first appearing from a source host that has never legitimately sourced DA auth (the web server), followed within a short window by bulk destructive file ops on a server and a terminal reboot. That cross-artifact correlation and per-account/per-host baselining is judgement-heavy → hunt. The durable core to hand upward once baselined: **DA logon whose source host is not on the admin-jumpbox allowlist** (Summiting Level-4 relationship observable, robust — the adversary cannot avoid authenticating from *somewhere* unexpected) is a candidate high-severity alert for detection-engineering; the built-in-tool destruction itself stays a hunt.

## Data sources required

- Windows Security 4624/4648 (logon / explicit-credential logon — Type 3/10, account + source host) + 4672 (privileged logon) — to spot DA auth from the web server
- Windows Security 4688 / Sysmon EID 1 (process create, command line) — `sdelete`, `format.exe`, `do.exe`, explorer bulk-delete context
- Sysmon EID 11 (file create) / EID 23 (file delete) burst on a server host; file-operation volume telemetry
- Windows System 1074/6006/6008 + Security 4608 (shutdown/dirty-reboot/unexpected-boot) — terminal event correlation
- AD Domain Admins group membership (to scope "which accounts count"); admin-jumpbox / source-host allowlist (baseline)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — DA logon from a never-before-seen source host, chained to a destruction burst and a reboot on the same host

```kusto
// 1) Domain Admin logon sourced from an unusual host (web server = handoff fingerprint)
let da_accounts = _GetWatchlist("DomainAdmins") | project AccountName = tolower(SearchKey);
let jumpbox_allow = _GetWatchlist("AdminJumpboxes") | project DeviceName = tostring(SearchKey);
let da_from_odd_host =
    SecurityEvent
    | where TimeGenerated > ago(21d)
    | where EventID in (4624, 4648) and LogonType in (3, 10)
    | extend acct = tolower(TargetAccount)
    | where acct in (da_accounts)
    | where isnotempty(WorkstationName) and WorkstationName !in (jumpbox_allow)
    | project LoginTime = TimeGenerated, acct, SourceHost = WorkstationName, DestHost = Computer, IpAddress;
// 2) Destruction burst on a host: SDelete / Format / mass delete
let destruction =
    union
      (DeviceProcessEvents
       | where TimeGenerated > ago(21d)
       | where FileName in~ ("sdelete.exe","sdelete64.exe","format.com","do.exe")
             or ProcessCommandLine has_any (@"format ", "/fs:", "/q /x", @"\\.\C:")
       | project EvtTime = TimeGenerated, DeviceName, actor = InitiatingProcessAccountName, ProcessCommandLine, kind="proc"),
      (DeviceFileEvents
       | where TimeGenerated > ago(21d) and ActionType == "FileDeleted"
       | summarize deletes = count() by DeviceName, bin(TimeGenerated, 5m), actor = InitiatingProcessAccountName
       | where deletes > 200                                  // bulk-delete burst
       | project EvtTime = TimeGenerated, DeviceName, actor, ProcessCommandLine = strcat("bulk_delete=", deletes), kind="filedel");
// 3) Terminal reboot on the same host
let reboots =
    Event
    | where TimeGenerated > ago(21d) and Source == "EventLog" and EventID in (6008, 6006, 1074)
    | project RebootTime = TimeGenerated, DeviceName = Computer;
// Chain: DA-from-odd-host  ->  destruction burst  ->  reboot, same DestHost, within 12h
da_from_odd_host
| join kind=inner (destruction) on $left.DestHost == $right.DeviceName
| where EvtTime between (LoginTime .. (LoginTime + 12h))
| join kind=leftouter (reboots) on $left.DestHost == $right.DeviceName
| where isnull(RebootTime) or RebootTime between (EvtTime .. (EvtTime + 6h))
| project LoginTime, acct, SourceHost, DestHost, EvtTime, kind, ProcessCommandLine, RebootTime
| order by LoginTime asc
```

## Triage guidance

- **Likely malicious:** a Domain Admin account authenticating *for the first time* from an internet-facing web server (or any host not on the jumpbox allowlist), followed within hours by `sdelete`/`format`/bulk File Explorer deletion on one or more servers and a terminal reboot the host does not recover from; presence of `C:\ProgramData\do.exe` or a DA-credential-validating binary anywhere in the chain; destruction hitting file servers / DCs rather than a single workstation. This is an active destructive operation.
- **Likely benign / expected:** scheduled decommissioning, disk-reprovisioning, or DBA/admin cleanup that uses `format`/`sdelete` from an approved jumpbox on a known change ticket; a DA logon from a host already on the allowlist; a lone reboot with no preceding destruction burst. Confirm against change-management and the source-host baseline before escalating.
- **Pivot next:** if the chain confirms, this is a live destructive incident — do **not** wait to finish documenting. Isolate the destination host(s) and the web-server source host, disable and rotate the implicated DA credential, preserve volume/MBR images before any reboot, and pivot to the web-shell (HUNT-03), the reverse-SOCKS/RDP tunnel, and wiper staging (detection pack T1561.001/.002, T1490). Escalate to incident-response-coordinator immediately.

## References

- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://blog.checkpoint.com/research/unveiling-void-manticore-structured-collaboration-between-espionage-and-destruction-in-mois/
- https://attack.mitre.org/techniques/T1078/002/
- https://attack.mitre.org/techniques/T1485/
- https://attack.mitre.org/techniques/T1529/
