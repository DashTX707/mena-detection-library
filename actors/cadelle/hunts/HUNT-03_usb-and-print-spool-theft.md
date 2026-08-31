# Hunt: Cadelspy peripheral surveillance — USB-insertion monitoring and print-spool document theft

- **Hypothesis:** If Backdoor.Cadelspy is resident, then an untrusted background process will register for device-arrival notifications (to detect USB/removable-media insertion) and will read the print-spool artifacts, intercepting documents the victim sends to the printer. The anomaly is an unexpected relationship plus a path/property mismatch: a non-print, non-storage-management process opening spool files under `C:\Windows\System32\spool\PRINTERS\` (`.SPL`/`.SHD`) and reacting to `WM_DEVICECHANGE`/`RegisterDeviceNotification` events that legitimate user apps have no reason to touch.
- **ATT&CK:**
  - T1120 — Peripheral Device Discovery (discovery)
- **Actor procedure:** Cadelspy monitors the infected computer for insertion of USB/removable-storage devices and extracts printer information, enabling it to intercept and steal documents the victim sends to the printer as well as data from attached peripherals. Stolen print documents and peripheral data are folded into the same `.cab` collection archive for exfiltration.
- **Why a hunt, not a rule:** Device-arrival notification and printer enumeration ride on standard OS notifications (`RegisterDeviceNotification`, `SetupDi*`, spooler APIs) that legitimate drivers, backup tools, and print utilities use constantly, so a bare API-call alert would drown in noise. The durable, hard-to-evade behavior is a *non-spooler* process reading `spool\PRINTERS\*.SPL` shadow files — reading the print queue is a technique-core action the operator cannot skip without giving up printed-document theft. Hunt that relationship and baseline which processes legitimately open the spool directory per host.

## Data sources required

- Sysmon EID 11 / EID 1 — file access/creation and process context for `C:\Windows\System32\spool\PRINTERS\*.SPL` and `*.SHD`
- Windows `Microsoft-Windows-PrintService/Operational` (EID 307 document-print) — to correlate what was printed with what the suspect process read
- EDR device-access / driver telemetry — `RegisterDeviceNotification`, `WM_DEVICECHANGE`, `SetupDiGetDeviceRegistryProperty`, removable-volume arrival (`\Device\...\Volume` mounts)
- Sysmon EID 13 — writes under `SYSTEM\...\Enum\USBSTOR` and `MountedDevices` reflecting removable-media insertion

## Query starting point

Platform: `Splunk SPL`

```
``` non-spooler processes touching print-spool shadow files ```
index=endpoint (EventCode=11 OR EventCode=1)
  (TargetFilename="*\\spool\\PRINTERS\\*.SPL" OR TargetFilename="*\\spool\\PRINTERS\\*.SHD")
| eval proc=lower(coalesce(Image,New_Process_Name))
| where NOT proc IN ("*\\spoolsv.exe","*\\printfilterpipelinesvc.exe","*\\printisolationhost.exe","system")
| stats values(TargetFilename) as spool_files values(proc) as procs
        earliest(_time) as first_seen by host, proc
``` corroborate the SAME process reacting to removable-device arrival ```
| join type=left host proc [
    search index=edr (api IN ("RegisterDeviceNotification","SetupDiGetDeviceRegistryProperty","GetVolumeInformation")
                      OR EventCode=13 TargetObject="*\\USBSTOR\\*")
    | eval proc=lower(Image)
    | stats values(api) as device_apis values(TargetObject) as usb_keys by host, proc ]
| eval usb_monitor=if(isnotnull(device_apis),"yes","no")
| table host, proc, spool_files, usb_monitor, device_apis, first_seen
```

## Triage guidance

- **Likely malicious:** A non-spooler, unsigned/unusually-located process opening `spool\PRINTERS\*.SPL` shadow-page files it never generated; the same process also registering device-arrival notifications and reading `USBSTOR` on media insertion; spool reads with no corresponding legitimate print-management tool installed; artifacts subsequently landing in a `.cab` staging folder (T1560).
- **Likely benign / expected:** The print spooler (`spoolsv.exe`), print-filter/isolation host processes, signed printer drivers and PDF/print-capture utilities, backup and DLP agents that legitimately index the spool or removable media. Baseline these and suppress. Removable-media indexing by AV/EDR is normal.
- **Pivot next:** If a non-spooler process is confirmed reading spool shadow files, correlate its process identifier back to HUNT-01 (multi-sensor capture) and HUNT-02 (discovery) — a match across all three is a high-confidence Cadelspy composite. **Escalate to incident-response-coordinator.** The stable "non-spooler process reads `spool\PRINTERS\*.SPL`" behavior is precise enough to hand to detection-engineering.

## References

- https://attack.mitre.org/software/S0454/
- https://attack.mitre.org/techniques/T1120/
- https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east/
- https://securityaffairs.com/42641/breaking-news/cadelle-and-chafer-iranian-hackers.html
- https://www.darkreading.com/attacks-breaches/iranian-groups-conducting-sophisticated-surveillance-on-middle-eastern-targets
