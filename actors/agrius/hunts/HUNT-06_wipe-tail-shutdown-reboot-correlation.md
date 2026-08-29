# Hunt: Agrius wipe-tail correlation — shutdown/reboot as the terminal step of a destruction chain (log-clear → boot-sector write → power cycle)

- **Hypothesis:** If an Agrius wiper has run to completion on a host, then a shutdown/reboot will appear not in isolation but as the *last link* of a destructive chain within a compressed window: log-clearing (scheduled task → all Windows Event Logs cleared), Volume Shadow Copy / VSS-service removal, a user-mode process opening a raw `\\.\PhysicalDrive0` handle and writing the boot sector, security/VSS service stops — and then the shutdown/reboot call. The shutdown alone is meaningless; the same host emitting *any* of those destructive precursors immediately before a shutdown/reboot is the finding.
- **ATT&CK:**
  - T1529 — System Shutdown/Reboot (impact) — MultiLayer / BFG Agonizer trigger shutdown/reboot to finalize destruction, leaving the endpoint unbootable
  - (correlated precursors, detection lane — referenced for chain context: T1070.001 event-log clear, T1490 VSS deletion, T1561.002 disk-structure wipe, T1489 service stop)
- **Actor procedure:** After corrupting disk structures — BFG Agonizer overwrites the first 6 sectors of `\\.\PhysicalDrive0`; MultiLayer wipes the first 512 bytes — Agrius wipers ensure the machine can no longer boot and then trigger a shutdown/reboot to render the endpoint inoperable, the terminal act of the theft-then-destroy operation. The reboot is deliberately the *end* so the victim discovers the damage on next power-on, after logs are cleared and shadow copies are gone.
- **Why a hunt, not a rule:** shutdown/reboot is one of the most common events in any environment — patch cycles, GPO restarts, user power-offs, maintenance windows generate thousands per day, so it is not remotely alertable on its own (Level 1 ephemeral). The value is purely *correlative and retrospective*: a reboot preceded within minutes by log-clearing, VSS/shadow-copy deletion, a raw physical-drive write, or an unexplained security-service stop on the same host. That temporal join across impact-precursor telemetry is analyst work — and because a wiper reboot often destroys local logs, this hunt also depends on off-host log forwarding (a visibility check in its own right).
- **Visibility-gap note:** if the destructive precursors are only in local Windows event logs and those are not forwarded off-host, the wipe erases the very evidence this hunt needs — treat absence of forwarded Security/System logs from at-risk servers as an actionable finding, not a clean result.

## Data sources required

- Windows System 1074 (initiated shutdown/reboot), 6006/6008 (clean/dirty shutdown), 1102 (Security log cleared), 104 (System log cleared) — **must be forwarded off-host**
- Sysmon EID 1 / 4688 — `shutdown.exe`, `wmic os ... reboot`, `InitiateSystemShutdown` callers; the initiating process lineage
- EDR raw-disk-write analytics (`\\.\PhysicalDrive` handle + write), VSS/shadow-copy deletion, service-stop events (chain precursors)
- SIEM with reliable cross-host time correlation

## Query starting point

Platform: `Splunk SPL`

```
(index=wineventlog source="WinEventLog:System" EventCode=1074)
| eval evt="shutdown", ekey=host, t_shut=_time
| append [
    search (index=wineventlog (source="WinEventLog:Security" EventCode=1102)
            OR (source="WinEventLog:System" EventCode=104))
    | eval evt="logclear", ekey=host, t_pre=_time ]
| append [
    search index=endpoint source=*Sysmon* (EventCode=1 (CommandLine="*vssadmin*delete*shadows*"
            OR CommandLine="*shadowcopy*delete*" OR CommandLine="*win32_shadowcopy*"))
    | eval evt="vss_delete", ekey=host, t_pre=_time ]
| append [
    search index=endpoint source=EDR:diskwrite raw_handle="\\\\.\\PhysicalDrive*"
    | eval evt="rawdisk", ekey=host, t_pre=_time ]
| stats values(evt) as events min(t_pre) as first_precursor max(t_shut) as shutdown_time
        by ekey
| where isnotnull(shutdown_time) AND mvcount(events)>=2
  AND (shutdown_time - first_precursor) < 1800
| eval lag_s = shutdown_time - first_precursor
| sort lag_s
```
Reads: a host where a shutdown/reboot is preceded within 30 minutes by log-clear, VSS deletion,
and/or a raw `\\.\PhysicalDrive` write is a wipe tail, not a maintenance reboot.

## Triage guidance

- **Likely malicious:** a shutdown/reboot on a server preceded within minutes by Security-log clear (1102) and/or System-log clear (104), shadow-copy deletion, or a raw `\\.\PhysicalDrive0` write — especially with no change/maintenance ticket; a shutdown initiated by an unusual process (a `%temp%`/renamed binary, not `TrustedInstaller`/WU/GPO); a cluster of such reboots across multiple hosts in a short window (mass wipe).
- **Likely benign / expected:** Patch-Tuesday and WSUS/SCCM-driven reboots; GPO/maintenance-window restarts; user-initiated power cycles; legitimate admin-cleared logs with a ticket. Baseline maintenance windows and patch schedules and suppress them.
- **Pivot next:** this is the tail of the kill chain — if any precursor+reboot correlation confirms, the host is likely already wiped; pivot to blast-radius (how many hosts show the same pattern), to the staging/exfil that preceded it (HUNT-01), the anti-forensics tooling (HUNT-04), and the entry vector (HUNT-05). A confirmed wipe tail is an active destructive incident — escalate to incident-response-coordinator immediately and prioritize containment of not-yet-detonated hosts. The precursor events (1102/104, VSS-delete, raw-disk-write) are individually high-fidelity and already routed to the detection lane; hand any newly-observed initiating-binary/command patterns to detection-engineering.

## References

- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/
- https://attack.mitre.org/groups/G1030/
