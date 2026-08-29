# Hunt: Agrius pre-wipe data-theft chain — bulk local/DB read → automated PII extraction → local staging → archive (the "steal-then-destroy" precursor)

- **Hypothesis:** If Agrius/Agonizing Serpens is preparing a destructive operation, then *before* any wiper fires we should observe a coherent theft-then-stage sequence on database and file servers: a non-DB-application process issuing bulk reads/SQL SELECTs and writing large CSVs, files (CSV/.dmp/archives) accumulating in a single working folder (observed `C:\windows\temp\s\`), and a `7zip`/archive utility spawning against that folder to produce `.7z`/`.ezip` bundles — all on the same host, in the same short window, driven by a suspicious parent (web-shell/`cmd.exe` lineage or a renamed binary), standing out from the slow drip of legitimate backup/ETL activity.
- **ATT&CK:**
  - T1005 — Data from Local System (collection) — bulk gather from DB and critical servers before wiping
  - T1119 — Automated Collection (collection) — Sqlextractor (`sql.net4.exe`) auto-queries SQL DBs and dumps PII to CSV
  - T1074.001 — Data Staged: Local Data Staging (collection) — staging into `C:\windows\temp\s\`
  - T1560.001 — Archive Collected Data: Archive via Utility (collection) — 7zip producing `.7z`/`.ezip`
- **Actor procedure:** In the 2023 Agonizing Serpens intrusions, Agrius ran a custom database extractor, Sqlextractor (`sql.net4.exe`), against SQL servers to identify and pull PII (ID numbers, passport scans, emails, addresses) into CSV files, gathered data from database and other critical servers, staged the loot in `C:\windows\temp\s\`, and archived it with 7zip into `.7z`/`.ezip` files ahead of exfiltration (PuTTY/pscp — detection lane) and terminal wiping. Theft is not the goal in itself; it is the reconnaissance-of-value step that precedes destruction and, per the fake-ransomware ruse, provides leak material.
- **Why a hunt, not a rule:** every primitive here has a massive benign base rate — DB servers issue bulk SELECTs constantly, backup/ETL jobs write large CSVs and `.dmp` files, and archiving is routine admin work. No single event is alertable without drowning the SOC. The durable signal (Summiting technique-core, Level 3–4) is the *sequence and co-location*: read → same-host stage folder → archive, executed by a process that is not the legitimate DB/backup application, within one short window. That correlation needs per-environment baselining of who normally reads bulk data and where backups legitimately land — analyst work, not a threshold.

## Data sources required

- Sysmon EID 11 (file create) — CSV/.dmp/.7z/.ezip writes, especially under `C:\windows\temp\*` and other non-standard staging paths
- Sysmon EID 1 / Windows Security 4688 — process create with command line + parent (7zip/`7z.exe`/`sql.net4.exe`, archive flags, unusual parents)
- Database audit logs / SQL Server audit — bulk SELECT volume by login and source process
- EDR file + process-lineage telemetry; DLP/file-classification hits on CSV containing PII

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=11
| eval f=lower(TargetFilename), creator=lower(Image)
| eval kind=case(
    match(f,"\.csv$"),"csv_dump",
    match(f,"\.(dmp|bak)$"),"raw_dump",
    match(f,"\.(7z|ezip|zip|rar)$"),"archive",
    1=1,null())
| where isnotnull(kind)
| eval stage_path=if(match(f,"(?i)\\\\windows\\\\temp\\\\s\\\\") OR match(f,"(?i)\\\\windows\\\\temp\\\\"),1,0)
| bin _time span=30m
| stats dc(kind) as kinds values(kind) as kinds_seen values(creator) as creators
        values(f) as files sum(stage_path) as staged_hits count by _time, host
| where (kinds>=2) OR (staged_hits>0 AND kinds>=1)
| sort - kinds
```

Pivot `creators` against known DB/backup binaries; treat `sql.net4.exe`, `7z*.exe` with archive flags, or any archive written under `\windows\temp\` by a `cmd.exe`/web-shell parent as high interest.

## Triage guidance

- **Likely malicious:** CSVs written by a process that is not the DB engine/backup agent (esp. `sql.net4.exe` or a renamed binary), then an archive created in the *same* folder minutes later; any staging under `C:\windows\temp\s\` or a fresh single-letter temp folder; archive/read lineage tracing back to `w3wp.exe`→`cmd.exe` (web shell) or a `%temp%`/`%public%` binary; bulk SQL SELECT volume from a login/host that never normally runs analytics.
- **Likely benign / expected:** scheduled backup jobs writing `.bak`/`.dmp` to backup volumes; ETL/reporting exporting CSV to known data-warehouse paths; admins zipping logs. Baseline the legitimate backup accounts, ETL service accounts, and their destination paths and suppress them.
- **Pivot next:** this is the flagship early-warning chain for a wiper actor — if confirmed, treat as pre-detonation and move fast. Pivot to exfiltration (pscp/WinSCP outbound SSH, detection lane), to the discovery burst that preceded it (HUNT-02), to the web-shell/valid-account entry (HUNT-05), and forward to the anti-forensic/wipe-tail hunts (HUNT-04, HUNT-06). Confirmed staging-before-destruction on a live host is an incident — escalate to incident-response-coordinator.

## References

- https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/
- https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/
- https://attack.mitre.org/groups/G1030/
