# Hunt: IOCONTROL rc-script persistence & systemd-masquerading on managed OT/IoT gateways

- **Hypothesis:** If CyberAv3ngers' IOCONTROL implant is resident on a managed Linux OT/IoT device (fuel controller, router, camera gateway, PLC front-end), then on the subset of devices that actually ship a shell + writable filesystem + collectable telemetry we should find its persistence footprint: an rc3.d init script (`/etc/rc3.d/S93InitSystemd.sh`) that was *created/modified* outside a vendor firmware-update window, a main binary named to blend in (`/usr/bin/iocontrol`) or a boot script masquerading as a legitimate systemd component, and a short-interval watchdog loop that relaunches a process every ~5 seconds. The core embedded PLC/HMI firmware is a telemetry black hole — the hunt deliberately pivots to the *managed* Linux gateways that front those devices, because that is the only tier where auditd/FIM/EDR can see the filesystem at all.
- **ATT&CK:**
  - T1037.004 — Boot or Logon Initialization Scripts: RC Scripts (persistence)
  - T1036.005 — Masquerading: Match Legitimate Name or Location (defense-evasion / "stealth")

- **Actor procedure:** IOCONTROL installs a backdoor as an rc3.d boot script at `/etc/rc3.d/S93InitSystemd.sh`; the script runs a watchdog loop that relaunches `/usr/bin/iocontrol` every 5 seconds if the process is not running, surviving reboots. It masquerades by naming its binary `iocontrol` under `/usr/bin` and its boot script `S93InitSystemd.sh` to imitate a legitimate systemd initialization component on the device.
- **Why a hunt, not a rule:** The exact known-bad names (`S93InitSystemd.sh`, `/usr/bin/iocontrol`) are Level-1 IOCs the actor changes trivially between victims and firmware families — a name-match rule ages out immediately and produces a false sense of coverage. The durable, robust signal is *relational and behavioural*: an rc-script created/altered on a device outside any authorized firmware-update change window, referencing a binary in a persistent respawn loop, on a device class that normally never mutates its init directory. That "new persistence artifact on an immutable-by-design appliance" judgement needs a per-device-class baseline of what init scripts are expected and when they legitimately change — baselining and change-window correlation that is analyst work, not a static rule. Where FIM exists on a homogeneous gateway fleet, "any write to `/etc/rc*.d/` outside a signed vendor update" is durable enough (Level-4 implementation-core) to hand to detection-engineering as an alert.

## Data sources required

- Managed-gateway auditd (`SYSCALL`/`PATH` records for `open`/`openat`/`rename`/`chmod` under `/etc/rc*.d/`, `/etc/init.d/`, `/usr/bin/`) or vendor FIM
- File-integrity monitoring baseline of the init directories per device model/firmware version (golden-image diff)
- Process inventory / `ps` telemetry for short-lived respawning parents (watchdog loop every ~5s)
- Vendor firmware-update change calendar / ticketing (to establish authorized change windows)
- Cross-device aggregation across the gateway fleet (same new init artifact on N devices)

## Query starting point

Platform: `Linux auditd (SOF-ELK / Elastic) — new or modified rc-script on a managed OT gateway, correlated against change windows`

```elasticsearch
# (a) auditd: any create/modify of an rc-script or /usr/bin binary on gateway fleet
event.module:auditd and auditd.data.syscall:(open* or rename* or link* or chmod)
  and file.path:("/etc/rc3.d/*" or "/etc/init.d/*" or "/etc/rc.local" or "/usr/bin/*")
  and not process.executable:("/usr/bin/dpkg" or "/usr/bin/opkg" or "/usr/bin/rpm"
       or "/usr/sbin/sysupgrade")            # exclude signed package/firmware tooling
| stats first=min(@timestamp), models=values(host.os.version),
        devices=dcount(host.name) by file.path, process.executable
| where NOT file.path in (golden_image_init_baseline)   # never-before-seen init artifact
| sort devices desc

# (b) watchdog respawn tell: same argv relaunching on a ~5s cadence
# ps/telemetry | bucket process.start_time by 10s
#   | where same (host.name, process.command_line) restarts >= 3 within 60s
#   | especially where process.executable resides in /usr/bin with a systemd-like name
```

Cross-check the file hash of any new `/usr/bin/*` artifact against Claroty's IOCONTROL sample SHA-256 `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498` as a pivot only — do not anchor the hunt on it.

## Triage guidance

- **Likely malicious:** a new script under `/etc/rc3.d/` created outside any vendor-update ticket, referencing a `/usr/bin` binary in a tight respawn loop; a binary whose name mimics a systemd/init component but lives in an unexpected path or lacks the vendor package's ownership/signature; the *same* new init artifact appearing across multiple same-model gateways in a short window (fleet-wide implant push).
- **Likely benign / expected:** legitimate vendor firmware updates and package installs rewrite init scripts and drop `/usr/bin` binaries — these should map to an authorized change window and signed package tooling (suppress `opkg`/`dpkg`/`sysupgrade`-driven changes). Genuine device watchdogs/supervisors (busybox init, monit, vendor keepalive) also respawn processes on a cadence — baseline the expected supervisor per model and exclude it.
- **Pivot next:** if a persistence artifact is confirmed, pivot on the *same device* to HUNT-02 (does the binary spawn shell commands / decrypt config at runtime?) and HUNT-03 (is it beaconing MQTT/TLS to an external broker on 8883?). A confirmed implant with live C2 on OT infrastructure is an active compromise → escalate to incident-response-coordinator; image the gateway before remediation because IOCONTROL carries a self-delete module (detection pack T1070.004).

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol
- https://attack.mitre.org/techniques/T1037/004/
- https://attack.mitre.org/techniques/T1036/005/
