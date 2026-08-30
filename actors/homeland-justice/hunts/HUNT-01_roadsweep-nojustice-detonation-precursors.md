# Hunt: Homeland Justice / Storm-0842 destructive end-chain precursors (ROADSWEEP encrypt + No-Justice wipe staging)

- **Hypothesis:** If Storm-0842's ~14-month dwell is about to culminate in the ROADSWEEP encrypt (GoXml.exe) and No-Justice/NACL raw-disk wipe (cl.exe + EldoS rwdsk.sys), then *before* the encrypt/wipe burst is observable we should see its enabling precursor sequence on the same hosts in a tight window: an unusual pre-impact **file-and-directory enumeration burst** (a single process touching thousands of files/volumes across many directories) fanning out into the mass encrypt/destroy. The hunt is framed to catch the discovery-into-detonation transition *before* impact, because once high-rate encryption or raw-disk overwrite is visible, recovery is already lost. This is the flagship: it stitches the discovery precursor to the two payload outcomes (encrypt and wipe) as one chain rather than alerting on either endpoint alone.
- **ATT&CK:**
  - T1083 — File and Directory Discovery (discovery) — hunt the pre-impact enumeration burst, not enumeration in isolation
  - T1486 — Data Encrypted for Impact (impact) — hunt the precursor/onset, not the completed encryption
  - T1485 — Data Destruction (impact) — hunt the precursor (raw-device handle / driver-mediated write onset), not the completed wipe

- **Actor procedure:** Per AA22-264A, after long dwell the actor launched ROADSWEEP (`GoXml.exe`, from `C:\ProgramData\Microsoft\Windows\`) via `win.bat` with arguments `1 2 3 4 5 6 7` to enumerate and encrypt files and drop a Homeland Justice note, and separately ran `cl.exe` (the No-Justice / ZEROCLEARE-lineage wiper) which loads the legitimate EldoS `rwdsk.sys` RawDisk driver to obtain raw block-level access and destroy file content and disk structures. Both payloads first enumerate files/volumes to select targets; the encrypt and wipe were distributed to many hosts from a central distribution point and detonated in a synchronized window.
- **Why a hunt, not a rule:** The encrypt and wipe themselves are LOW detection-feasibility precisely because by the time high-rate encryption or a raw `\\.\PhysicalDrive` overwrite is observed, the impact is already occurring — an alert on the endpoint fires too late to preserve data. File-and-directory enumeration, meanwhile, is ubiquitous and near-zero-signal on its own (backup, indexing, AV scans all enumerate at scale), so it can't be a standalone rule either. The discriminating signal is *relational and sequential*: an abnormal enumeration burst by an unfamiliar process running from a masquerading path, immediately transitioning into rapid many-directory file modification (rename/extension change/entropy jump) or a raw-device write handle — the same process, the same short window, fanning across hosts. That correlation and cross-host baselining is judgement-heavy → hunt. The durable core to hand to detection-engineering (Summiting Level 4, implementation-core) is: *a single non-allowlisted process that enumerates thousands of files across many directories and then modifies them at high rate OR acquires a raw `\\.\PhysicalDrive` write handle* — robust because the adversary cannot abandon enumerate-then-impact without abandoning the technique.

## Data sources required

- Sysmon EID 1 (process create, with command line) + EID 11 (file create/modify) — enumeration-to-modification transition per process
- EDR file-operation telemetry (DeviceFileEvents): per-process file-touch rate, distinct-directory fan-out, extension-change / rename bursts
- Sysmon EID 6 (driver load) for `rwdsk.sys` + EDR raw-device `CreateFile` on `\\.\PhysicalDrive*` (cross-ref detection-pack T1543.003 / T1561.*)
- Cross-host aggregation (same binary name/hash enumerating-then-modifying across N endpoints in a window)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — per-process enumeration burst transitioning into mass file modification, aggregated across hosts

```kusto
// Processes that both enumerate widely AND modify files at high rate in a short window
let win = 15m;
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| summarize
    filesTouched   = dcount(FolderPath),
    dirsSpanned    = dcount(strcat_array(array_slice(split(FolderPath,"\\"),0,4),"\\")),
    modBurst       = countif(ActionType in ("FileModified","FileRenamed")),
    firstMod       = min(Timestamp), lastMod = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256,
       bin(Timestamp, win)
| where filesTouched > 500 and dirsSpanned > 20 and modBurst > 500   // enumerate-then-impact
| where InitiatingProcessFileName !in~ (
        "wbengine.exe","VeeamAgent.exe","MsMpEng.exe","SearchIndexer.exe","backup.exe") // baseline
// Fan-out: same binary exhibiting the pattern across multiple hosts = synchronized detonation
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 25),
            earliest = min(firstMod) by InitiatingProcessFileName, InitiatingProcessSHA256
| order by hosts desc, earliest asc

// Pivot companion (raw-disk destruction onset): DeviceEvents ActionType == "DriverLoad"
//   where FileName =~ "rwdsk.sys" OR process opens \\.\PhysicalDrive* write handle — cross-ref T1561.*
```

## Triage guidance

- **Likely malicious:** an unfamiliar or newly-seen binary (esp. from `C:\ProgramData\Microsoft\Windows\` or another masquerading path — see HUNT-02) that enumerates thousands of files across dozens of directories and then renames/rewrites them at high rate, dropping a uniformly-named note per directory; the same binary exhibiting the pattern across multiple hosts in a synchronized window; enumeration burst immediately preceded by `vssadmin delete shadows`, a `bb.bat` taskkill loop, or a `rwdsk.sys` driver load (detection-pack T1490/T1489/T1543.003); any process acquiring a raw `\\.\PhysicalDrive` write handle after enumerating volumes. This is imminent/active destruction.
- **Likely benign / expected:** backup agents, AV/EDR scans, search indexers, and migration/dedup tools enumerate and touch files at scale on a known cadence from known signed binaries in known paths — allowlist them by process + path + signer. Bulk *reads* without a modification burst are benign enumeration. A single known-good tool on one host is expected; an unknown binary enumerating-then-modifying and fanning out is not.
- **Pivot next:** if the enumerate-then-impact chain is confirmed on any host this is a live destructive incident — stop hunting and **escalate to incident-response-coordinator immediately**; isolate affected and fan-out-target hosts, block the binary/driver hash fleet-wide, preserve volume/MBR images before reboot, and pivot to the distribution path (print-server RDP + admin-share copies — detection-pack T1021/T1570) and the re-entry vector (HUNT-03). Pre-position recovery; assume shadow copies are already gone.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a
- https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/
- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1486/
- https://attack.mitre.org/techniques/T1485/
