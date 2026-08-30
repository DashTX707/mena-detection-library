# Hunt: Moses Staff / StrifeWater RAT collection cluster (screen-capture + local-data theft staging)

- **Hypothesis:** If the StrifeWater RAT is resident and operating in its hack-and-leak collection phase, then a single masquerading process (running as `calc.exe` from a non-standard path) should exhibit the RAT's collection behavior clustered together: invoking screen-capture APIs (`BitBlt`/`GetDC`/GDI) on a cadence, then performing bulk local file reads and staging that data to a working directory ahead of exfiltration. Neither screen-capture nor local file reads is meaningful in isolation — the hunt keys on the *unexpected relationship* of both behaviors originating from the same non-browser, non-office process, in a collect-then-stage sequence.
- **ATT&CK:**
  - T1113 — Screen Capture (collection) — RAT screenshotting the host for the C2
  - T1005 — Data from Local System (collection) — bulk local data theft ahead of leak

- **Actor procedure:** Per Cybereason, StrifeWater RAT (masquerading as the Windows calculator) captures screenshots of the compromised host and sends them to its C2, and — consistent with Moses Staff's hack-and-leak model — steals data from local systems before the destructive encryption stage, with the stolen data later published via the leak site and Telegram. The RAT profiles the host and can download further modules to extend collection.
- **Why a hunt, not a rule:** Screen-capture APIs are used by every screen-sharing, remote-support, snipping and conferencing tool; bulk local file reads are what backup, indexing and search do all day. Alerting on either produces overwhelming noise. The huntable signal is the *behavioral cluster on one anomalous process* — screen-capture + bulk staged reads from a binary named `calc.exe` but running outside `System32`, ideally with the network beacon (→ HUNT-06) attached. That cross-behavior, process-lineage judgement is analyst work; the durable core — screen-capture API use by a process whose on-disk name is a system binary running from a non-standard path — could be scoped to detection-engineering if the masquerade primitive (HUNT-05) is confirmed first.

## Data sources required

- EDR API-telemetry / Sysmon (screen-capture GDI calls, or module loads of `gdi32`/`user32` by anomalous processes)
- Sysmon EID 1 (process create, with Image path + OriginalFileName) + EID 11 (file create) — staging directory writes
- EDR file-access telemetry — bursts of reads across many user document paths by one process
- Sysmon EID 7 (image/module load) for the masquerading `calc.exe`
- Network beacon telemetry to correlate collection with exfil (cross-ref HUNT-06)

## Query starting point

Platform: `KQL / Microsoft Defender XDR` — one masquerading process doing screen-capture AND bulk staged reads

```kusto
// (a) processes named like a system binary but running from a non-standard path
let masq = DeviceProcessEvents
    | where TimeGenerated > ago(14d)
    | where FileName in~ ("calc.exe","svchost.exe")
    | where FolderPath !startswith @"C:\Windows\System32"
        and FolderPath !startswith @"C:\Windows\SysWOW64"
    | project DeviceName, ProcId = InitiatingProcessId, ProcName = FileName, FolderPath, TimeGenerated;
// (b) bulk local file reads staged to a working dir by that same process
let staging = DeviceFileEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "FileCreated"
    | where FolderPath has_any (@"\Users\Public", @"\AppData\Local\Temp", @"\ProgramData")
    | summarize files = dcount(FileName), bytes = sum(FileSize)
              by DeviceName, InitiatingProcessId, bin(TimeGenerated, 1h)
    | where files >= 50;                                 // bulk staging
masq
| join kind=inner staging on DeviceName, $left.ProcId == $right.InitiatingProcessId
| order by files desc
// Correlate with screen-capture: DeviceEvents where ActionType has "ScreenCapture"
//   or gdi32/BitBlt API telemetry attributed to the same InitiatingProcessId.
```

## Triage guidance

- **Likely malicious:** a `calc.exe`/`svchost.exe` running from `C:\Users\Public` or a temp path that both invokes screen-capture APIs and stages dozens-to-hundreds of files into a working directory in a compressed window; the same process holding an HTTP beacon (→ HUNT-06); collection immediately preceding the destructive precursors (→ HUNT-01) — this is hack-and-leak staging.
- **Likely benign / expected:** remote-support/conferencing tools (Teams, Zoom, TeamViewer), snipping/screenshot utilities, and backup/indexing agents legitimately screen-capture or read many files — allowlist their signed images and known paths. Genuine `calc.exe` runs only from `System32`/`SysWOW64`; anything named `calc.exe` elsewhere is inherently suspect. A signed backup agent reading many files on schedule is expected; an unsigned masquerading process doing so is not.
- **Pivot next:** dump and hash the masquerading binary (→ HUNT-05 sample analysis for OriginalFileName/entropy), pull its network connections (→ HUNT-06 XOR-C2 / exfil), and check for the Firefox-browser-agent scheduled task and self-deletion tail. If a live RAT is confirmed collecting data, this precedes destruction → escalate to incident-response-coordinator and preserve the staging directory before it is wiped.

## References

- https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations
- https://attack.mitre.org/techniques/T1113/
- https://attack.mitre.org/techniques/T1005/
