# Hunt: APT33 / Shamoon-nexus disk-wipe precursors (pre-detonation early warning)

- **Hypothesis:** If the assessed Shamoon/StoneDrill destructive capability is being staged in our environment, then *before* the wipe fires we should observe its enabling precursors — the load of an unusual signed low-level disk driver (RawDisk / ElRawDisk-style) by a non-storage process, and abnormal acquisition of a raw `\\.\PhysicalDrive0` / `\\.\C:` write handle by a non-standard process — appearing near-simultaneously across many hosts, alongside anti-forensic staging (event-log clears, recovery deletion). The hunt is framed to catch the driver-load and raw-write-handle **before** disk content/structure is overwritten, because after impact the evidence is gone.
- **ATT&CK:**
  - T1561.001 — Disk Wipe: Disk Content Wipe (impact) — hunt the precursor, not the wipe
  - T1561.002 — Disk Wipe: Disk Structure Wipe / MBR overwrite (impact) — hunt the precursor, not the wipe

- **Actor procedure:** In the FireEye-assessed Shamoon/StoneDrill nexus, APT33-linked operators deployed a wiper that used a signed RawDisk-style kernel driver to gain direct disk access, then overwrote file content and the Master Boot Record / partition structures — rendering thousands of workstations unbootable. The malware propagated worm-like using valid accounts and admin shares to detonate across many hosts at a scheduled time, typically preceded by defense tampering and log destruction.
- **Why a hunt, not a rule:** By the time the content/structure overwrite is *observed*, the data is already destroyed — an alert on the wipe itself fires too late to matter, so the value is entirely in catching the precursor. But signed disk drivers and raw-disk handles have legitimate uses (disk imaging, backup, forensics, partitioning, EDR itself), giving a base rate too high for a standalone rule; the discriminating signal is *stacked and relational*: an unfamiliar signed driver + raw-write handle by a non-storage process + the same behavior fanning out across many hosts in a short window + co-occurring log clears. That correlation and cross-host baselining is judgement-heavy → hunt. The robust core — a raw `\\.\PhysicalDrive` write handle acquired by a process that is not on the known storage/backup allowlist (Level-4 implementation-core) — is a candidate to hand to detection-engineering as a high-severity alert once the allowlist is built.

## Data sources required

- Sysmon EID 6 (driver load, with signature/hash) + kernel driver inventory
- Sysmon EID 1 (process create) + EID 10 (process access) + EDR raw-device-handle / `CreateFile` on `\\.\PhysicalDrive*` telemetry
- Windows Security 1102 (audit log cleared) + `wevtutil cl` execution; System 104
- Recovery-inhibition command execution (vssadmin/wbadmin/bcdedit — cross-ref detection pack T1490)
- Cross-host aggregation (same driver hash / same behavior across N endpoints in a window)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — never-before-seen signed disk driver + raw-write handle, aggregated across hosts

```kusto
// (a) Unusual disk-driver load: filter to drivers not seen in the 60d fleet baseline
let baseline = DeviceEvents
    | where TimeGenerated between (ago(60d)..ago(2d))
    | where ActionType == "DriverLoad"
    | summarize by SHA1 = tostring(parse_json(AdditionalFields).SHA1);
DeviceEvents
| where ActionType == "DriverLoad"
| extend SHA1 = tostring(parse_json(AdditionalFields).SHA1),
         Signer = tostring(parse_json(AdditionalFields).Signer)
| where SHA1 !in (baseline)                          // never-before-seen driver
| where FileName has_any ("rawdisk","elrawdisk","drdisk","diskcryptor") or Signer has "Eldos"
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 25),
            first = min(TimeGenerated) by SHA1, FileName, Signer
| where hosts >= 2                                    // fan-out = pre-detonation staging
| order by hosts desc

// (b) Raw physical-drive write handle by a non-storage process (precursor to overwrite)
// DeviceProcessEvents / Sysmon | where ProcessCommandLine has_any (@"\\.\PhysicalDrive", @"\\.\C:")
//   and FolderPath !in (known backup/imaging/EDR allowlist)
```

## Triage guidance

- **Likely malicious:** a never-before-seen signed disk driver loading on multiple hosts in a short window; a raw `\\.\PhysicalDrive0` write handle acquired by a process running from `%TEMP%`/user-writable path or a randomly named service; driver load immediately followed by 1102 log clears and vssadmin/bcdedit recovery deletion; any of the above fanning out via admin shares/PsExec across the estate — this is imminent-wipe staging.
- **Likely benign / expected:** disk-imaging/backup suites (Acronis, Veeam), partition tools, forensic acquisition, and EDR/AV agents legitimately load disk drivers and open raw handles — allowlist their signers/hashes/paths; scheduled backups touch raw volumes on a known cadence. A single host with a known-good tool is expected; fan-out of an *unknown* driver is not.
- **Pivot next:** if precursors are confirmed, this is a race — isolate affected hosts, block the driver hash fleet-wide, preserve MBR/volume images, and pivot to the propagation path (valid accounts + admin shares — HUNT-04 for the creds, detection pack T1021/T1078). Active wiper staging is a live destructive incident → escalate to IR immediately and pre-position recovery.

## References

- https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage
- https://attack.mitre.org/techniques/T1561/001/
- https://attack.mitre.org/techniques/T1561/002/
- https://attack.mitre.org/groups/G0064
