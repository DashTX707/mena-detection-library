# Hunt: Moses Staff / DCSrv destructive end-chain precursors (encrypt-destroy-reboot early warning)

- **Hypothesis:** If Moses Staff's DCSrv destructive encryptor is being staged in our environment, then *before* drives are encrypted and the machine is rebooted behind the DiskCryptor bootloader we should observe its enabling precursors clustered on the same host in a short window: a newly registered service (DCUMSrv/DCDrv or a randomly named service) loading the DiskCryptor kernel driver (`dcrypt.sys`), a user-mode/service process obtaining a raw `\\.\PhysicalDrive0` write handle, and — the terminal tell — an unexpected process issuing a `SeShutdownPrivilege` reboot immediately after. The hunt targets the driver-load + raw-write-handle + reboot correlation *before* volume encryption completes, because once DCSrv reboots the host into the locked bootloader the evidence and the data are both gone.
- **ATT&CK:**
  - T1486 — Data Encrypted for Impact (impact) — hunt the precursor, not the encryption
  - T1485 — Data Destruction (impact) — hunt the precursor, not the destruction
  - T1529 — System Shutdown/Reboot (impact) — the terminal step, meaningful only in correlation

- **Actor procedure:** Per Check Point, PyDCrypt decrypts and deploys DCSrv (built on the open-source DiskCryptor driver) across the network. On each host DCSrv registers the DCUMSrv user-mode service (masquerading as svchost.exe) and the DCDrv driver service, loads the DiskCryptor kernel driver, and issues IOCTLs (`DC_CTL_ENCRYPT_START`, `DC_CTL_ENCRYPT_STEP`) to encrypt every drive C: through Z:. It overwrites the boot-loader with a custom DiskCryptor bootloader, then reboots the machine so it comes up locked. There is no ransom demand and no decryption — the intent is destruction, and the flawed scheme leaves data functionally destroyed regardless.
- **Why a hunt, not a rule:** By the time encryption or the boot-overwrite is *observed*, the host is being destroyed — an alert on the impact itself fires too late. The precursors, however, each have legitimate uses: services get created constantly, DiskCryptor is a real admin tool in some shops, and reboots are trivially common. No single precursor carries a base rate low enough to alert on alone. The discriminating signal is *stacked and relational*: an unknown service + `dcrypt.sys` load by a non-storage process + raw physical-drive write handle + an out-of-band reboot, all on the same host within minutes, and fanning out across many hosts near-simultaneously. That cross-host correlation and baselining is judgement-heavy → hunt. The robust core — a raw `\\.\PhysicalDrive0` write handle acquired by a process not on the storage/backup allowlist (Level-4 implementation-core on the Summiting scale) — is durable and precise enough to hand to detection-engineering as a high-severity standalone alert once the allowlist exists.

## Data sources required

- Sysmon EID 6 (driver load, with signature/hash) — DiskCryptor `dcrypt.sys` load; kernel driver inventory
- Sysmon EID 1 / EDR process-create + EID 10 (process access) + raw-device `CreateFile` on `\\.\PhysicalDrive*` telemetry
- Windows System EID 7045 / Security 4697 (new service install) — DCUMSrv / DCDrv / random service names
- Windows System EID 1074 / 6006 (shutdown/reboot initiated) + process attribution for the reboot caller
- Cross-host aggregation (same driver hash / same service / same behavior across N endpoints in a window)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — stack DiskCryptor driver load + raw-disk write handle + service install on one host, aggregated across the fleet

```kusto
// (a) DiskCryptor driver load on hosts with no sanctioned disk-encryption deployment
let dcdriver = DeviceEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "DriverLoad"
    | extend SHA1 = tostring(parse_json(AdditionalFields).SHA1),
             Signer = tostring(parse_json(AdditionalFields).Signer)
    | where FileName =~ "dcrypt.sys" or Signer has "DiskCryptor" or FileName has "diskcryptor"
    | project TimeGenerated, DeviceName, DriverSHA1 = SHA1, Signer;
// (b) Suspicious service install near the driver load (DCUMSrv/DCDrv or random name)
let svc = DeviceEvents
    | where TimeGenerated > ago(14d)
    | where ActionType == "ServiceInstalled"
    | extend SvcName = tostring(parse_json(AdditionalFields).ServiceName)
    | where SvcName has_any ("DCUMSrv","DCDrv","dcrypt") or SvcName matches regex @"^[A-Za-z0-9]{8,}$"
    | project SvcTime = TimeGenerated, DeviceName, SvcName;
dcdriver
| join kind=inner svc on DeviceName
| where abs(datetime_diff('minute', TimeGenerated, SvcTime)) <= 30
| summarize hosts = dcount(DeviceName), hostset = make_set(DeviceName, 25),
            first = min(TimeGenerated) by DriverSHA1, Signer, SvcName
| order by hosts desc                                   // fan-out = mass detonation staging

// (c) Correlate with a raw physical-drive write handle by a non-storage process, and an
//     out-of-band reboot on the same host within the following few minutes:
// DeviceProcessEvents | where ProcessCommandLine has_any (@"\\.\PhysicalDrive0")
//   and FolderPath !in (known backup/imaging/EDR allowlist)
// DeviceEvents | where ActionType == "ShutdownEvent"  // caller != winlogon/user-initiated
```

## Triage guidance

- **Likely malicious:** `dcrypt.sys` (or an unknown-signer disk driver) loading on a host with no sanctioned DiskCryptor/BitLocker rollout, paired with a DCUMSrv/DCDrv or random-named service install within minutes; a raw `\\.\PhysicalDrive0` write handle from a process in `%TEMP%`/`C:\Users\Public`/an unsigned binary; the same driver+service pattern fanning out across many hosts near-simultaneously; an out-of-band reboot issued by that process seconds after the raw-disk writes — this is imminent destructive detonation.
- **Likely benign / expected:** sanctioned disk-encryption (BitLocker, a deliberately deployed DiskCryptor), backup/imaging suites (Acronis, Veeam), and EDR agents legitimately load disk drivers, open raw handles, and reboot on a known cadence — allowlist their signers/hashes/paths/service names. A single host running a known-good tool on schedule is expected; simultaneous fan-out of an *unknown* driver+service is not.
- **Pivot next:** if precursors are confirmed this is a race against detonation — isolate affected hosts immediately, block the driver hash and service name fleet-wide, preserve MBR/volume images, and pivot up the chain to the propagation path (valid-account fan-out — HUNT-02) and the web-shell/PyDCrypt origin. Active DCSrv staging is a live destructive incident → escalate to incident-response-coordinator now and pre-position recovery.

## References

- https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/
- https://attack.mitre.org/techniques/T1486/
- https://attack.mitre.org/techniques/T1485/
- https://attack.mitre.org/techniques/T1529/
