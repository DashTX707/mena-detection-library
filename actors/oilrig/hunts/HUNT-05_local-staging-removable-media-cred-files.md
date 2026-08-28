# Hunt: OilRig staging & harvesting — %TEMP% staging, USB capture, credentials in files

- **Hypothesis:** If OilRig is preparing data for exfil, then a host will show payload/credential-stealer output staged in `%TEMP%` (or similar), unexpected USB-traffic capture via Wireshark's `usbcapcmd`, and processes reading credential-bearing files — a staging footprint that precedes the outbound transfer.
- **ATT&CK:**
  - T1074.001 — Data Staged: Local Data Staging (collection)
  - T1025 — Data from Removable Media (collection)
  - T1552.001 — Unsecured Credentials: Credentials In Files (credential-access)
- **Actor procedure:** OilRig **stages stolen files from browser-data and credential-stealer tools in `%TEMP%`**, uses **Wireshark's `usbcapcmd` utility to capture USB traffic**, and uses credential-dumping tools (e.g. LaZagne) that harvest **credentials stored in files** across the system.
- **Why a hunt, not a rule:** `%TEMP%` staging is extremely noisy and common; reading credential-bearing files and USB capture leave little discrete signal on their own. The value is correlating staging file-writes with the process that produced them and with prior collection/credential activity — file-access-telemetry work that needs baselining, not a threshold alert.

## Data sources required

- Sysmon EID 11 (file create/write) in `%TEMP%`, `%LOCALAPPDATA%\Temp`, `\ProgramData`
- Sysmon EID 1 / 4688 for `usbcapcmd.exe` / `dumpcap.exe` / `tshark.exe` execution
- EDR file-access telemetry for reads of `*.kdbx`, `*.ovpn`, `web.config`, `unattend.xml`, `*.ppk`, `id_rsa`, `credentials`, `*.rdp`

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint (source=*Sysmon* EventCode=11) OR (source=*Sysmon* EventCode=1)
| eval tgt=lower(coalesce(TargetFilename, Image))
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line))
| eval sig=case(
    match(tgt,"\\\\(temp|programdata)\\\\.*\.(zip|rar|7z|dat|tmp|log|txt)$"),"staging",
    match(cmd,"usbcapcmd|dumpcap|tshark"),"usb_capture",
    match(tgt,"(\.kdbx|\.ovpn|\.ppk|id_rsa|unattend\.xml|web\.config|\.rdp|credentials)$"),"cred_file",
    1=1,null())
| where isnotnull(sig)
| bin _time span=30m
| stats values(sig) as signals dc(sig) as kinds values(tgt) as files values(ParentImage) as parents by _time, host, user
| where kinds >= 1
| sort - kinds
```

## Triage guidance

- **Likely malicious:** archive/`.dat` files written to `%TEMP%`/`\ProgramData` by a non-installer, unsigned process; `usbcapcmd`/`tshark` executed on a workstation with no packet-capture business need; a script-host or backdoor process reading `.ppk`/`id_rsa`/`web.config`/`.kdbx`.
- **Likely benign / expected:** installers and updaters staging in `%TEMP%`; legitimate network engineers running Wireshark; backup/DLP agents touching config files. Baseline by process publisher and host role.
- **Pivot next:** map staged files back to the collecting process (HUNT-04); check for the subsequent outbound transfer (HUNT-01) and file-deletion cleanup (HUNT-08); if credential files were read, treat as credential-access and escalate.

## References

- https://attack.mitre.org/groups/G0049/
