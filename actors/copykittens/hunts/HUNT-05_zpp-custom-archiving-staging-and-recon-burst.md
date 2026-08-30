# Hunt: CopyKittens — ZPP custom-method archiving, local staging, and the pre-exfil recon burst

- **Hypothesis:** If CopyKittens is preparing to exfiltrate, then just before the DNS/HTTP egress (HUNT-01) there is a short pre-exfil sequence on one host: a *recon burst* — the implant enumerates system information and running processes within a tight window to profile the host and pick injection/collection targets — followed by **custom-method archiving** (the ZPP console utility / bundled Ionic.Zip/DotNetZip) that produces a non-standard, high-entropy compressed blob staged in a temp/working directory. Because ZPP is a self-developed archiver rather than 7-Zip/WinRAR/`tar`, the staged output evades signature-based archive detection and does not carry a standard ZIP/RAR magic-byte or a familiar archiver command line — so the tell is a high-entropy file of nonstandard format written by an unusual process, temporally clustered with (a) a recon burst and (b) the collection cluster (HUNT-04). Any one — a systeminfo call, a temp-dir write, a compressed file — is nothing; the ordered sequence recon-burst → collect → custom-archive → stage on one host, ahead of a DNS egress, is the finding.
- **ATT&CK:**
  - T1560.003 — Archive Collected Data: Archive via Custom Method (collection) — ZPP self-developed archiver bundles data with a nonstandard routine; hunted via file-format/entropy analysis of staged output that lacks standard archive magic-bytes/command line.
  - T1082 — System Information Discovery (discovery) — Matryoshka/loader profiles OS and host config; hunted only inside a tight recon-burst window correlated to the implant, not as a standalone event.
  - T1057 — Process Discovery (discovery) — implant enumerates processes to pick injection targets / spot security tooling; hunted via process-lineage correlation within the same recon burst.

- **Actor procedure:** Before exfiltration, Matryoshka/loader components collect system information (OS, configuration) to profile the host and tailor follow-on payloads (T1082) and enumerate running processes to select injection targets and detect analysis/security tooling (T1057). Collected files, passwords, keystrokes and screenshots (HUNT-04) are then bundled using ZPP — a self-developed compression/archiving console utility (with bundled Ionic.Zip/DotNetZip) — rather than an off-the-shelf archiver (T1560.003), and staged locally in temp/working directories (detection pack T1074.001) before egress over the DNS/HTTP C2 channel (HUNT-01, detection pack T1041/T1048.003). The custom archiver is deliberately nonstandard so its output evades archive-signature detection.
- **Why a hunt, not a rule:** System-information and process enumeration are ubiquitous, near-zero-signal operations run constantly by legitimate software, management agents and users — a standalone rule is pure noise. And ZPP's whole point is to *not* look like a known archiver, so there is no `rar.exe a -hp` command line or ZIP magic-byte to key an alert on. The signal exists only in the **temporal ordering and co-location**: a recon burst (systeminfo + process-list) tightly clustered with a collection cluster and a nonstandard high-entropy staged file, on one host, ahead of egress — a sequence-and-correlation judgement, not a single observable. If a stable, specific artifact of ZPP's output format emerges (a consistent header/entropy profile), hand *that* file-format signature to detection-engineering; the recon burst and generic staging stay hunt-side.

## Data sources required

- EDR process-creation + command-line for recon commands (`systeminfo`, `tasklist`, `ver`, WMI `Win32_OperatingSystem`, `Get-Process`) and for the archiver/loader process lineage
- File-write telemetry with size/entropy on temp/working directories; a lightweight entropy/magic-byte enrichment on newly-written files (flag high-entropy files lacking standard archive/media magic-bytes)
- Sysmon EID 1/7 (process + module load) to attribute the recon burst and the archive write to the same implant lineage
- Baseline of legitimate archiver usage, backup/compression jobs, and inventory/management-agent recon for suppression

## Query starting point

Platform: `Splunk SPL` — sequence a recon burst with a nonstandard high-entropy staged file on one host

```spl
(index=edr sourcetype=process_creation
   (process IN ("systeminfo.exe","tasklist.exe","ver.exe","whoami.exe") OR
    CommandLine="*Win32_OperatingSystem*" OR CommandLine="*Get-Process*"))
| bin _time span=10m
| stats dc(process) as recon_variety values(process) as recon_cmds
        by host, _time, parent_process, parent_process_guid
| where recon_variety >= 3                                     
| join type=inner host parent_process_guid
   [ search index=edr sourcetype=file_write
       (file_path="*\\Temp\\*" OR file_path="*\\AppData\\*" OR file_path="*\\Users\\Public\\*")
     | eval nonstd_archive = if(entropy>7.2 AND NOT match(magic_bytes,"^(PK|Rar!|7z|BZh|\\x1f\\x8b)"), 1, 0)
     | where nonstd_archive=1 AND size_bytes > 1048576         
     | stats values(file_path) as staged_files values(process) as writer_proc
             min(_time) as archive_time by host, parent_process_guid ]
| eval seq_ok = if(archive_time >= _time, 1, 0)               
| where seq_ok=1
| table host parent_process recon_cmds writer_proc staged_files _time archive_time
```
Corroborate survivors with the collection cluster (HUNT-04) on the same host and a subsequent DNS/HTTP egress (HUNT-01) within the following hours.

## Triage guidance

- **Likely malicious:** a tight recon burst (systeminfo + process-list + host/user enumeration, 3+ variety in ~10 min) sharing a parent lineage with a subsequent write of a large, high-entropy file that **lacks** a standard archive/media magic-byte, in a temp/public/AppData path, written by an unusual (non-archiver, unsigned, rundll32-hosted) process — especially when the same host shows HUNT-04 collection and a following DNS egress. The nonstandard format is the ZPP fingerprint.
- **Likely benign / expected:** management/inventory agents (SCCM, asset scanners) run recon commands broadly and on a schedule; legitimate backup and compression jobs write large high-entropy archives — but those carry standard magic-bytes and known archiver lineage, so the magic-byte/entropy filter should exclude them; encrypted backup blobs and media files are high-entropy by nature — confirm the writer and the absence of a benign explanation. A recon command alone, or a staged archive alone, is expected; the ordered burst→custom-archive sequence on one lineage is not.
- **Pivot next:** if the sequence holds, treat the staged blob as a pre-exfil package — pivot to the egress (HUNT-01 Matryoshka DNS, detection pack T1041/T1048.003), the collection source (HUNT-04), and persistence (detection pack T1547.001/T1053.005). Recover and analyze the staged file's format to confirm ZPP and to derive a durable output-format signature for detection-engineering. A confirmed staged-then-exfiltrated package is active data theft — escalate to incident-response-coordinator and scope what left.

## References

- https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf
- https://attack.mitre.org/groups/G0052/
- https://attack.mitre.org/techniques/T1560/003/
- https://attack.mitre.org/techniques/T1082/
- https://attack.mitre.org/techniques/T1057/
