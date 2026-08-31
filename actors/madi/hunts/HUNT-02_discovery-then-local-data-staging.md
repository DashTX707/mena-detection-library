# Hunt: Broad file-type enumeration followed by same-process local data staging

- **Hypothesis:** If Madi-style collection is underway, then a single process will first *enumerate* the disk for a broad set of document/image data types (~27 in the original) and then *read and stage* the matching files into a working directory alongside keylog/screenshot output — so the same process shows a burst of directory listing / file-open activity across many extensions in a short window, immediately followed by reads of the hit files and writes into one staging folder. Discovery alone is noise; discovery-then-collection on the same non-indexer process is the finding.
- **ATT&CK:**
  - T1083 — File and Directory Discovery (discovery)
  - T1005 — Data from Local System (collection)
- **Actor procedure:** Madi's backdoor enumerated the victim's disk structure searching for ~27 data file types (documents, contracts, images), then collected the sensitive files — staging stolen documents together with keylogged data and screenshots for HTTP upload to the C2 servers, which doubled as stolen-data drops.
- **Why a hunt, not a rule:** File and directory enumeration is constant and legitimate (search indexers, backup agents, AV scans, users browsing), so raw enumeration can't be alerted. The durable behavioural signal is the *sequence and locality*: one process that lists broadly, then reads only the matching data-type hits, then concentrates them into a single staging path — a relationship that needs baselining of which processes legitimately touch documents at scale.

## Data sources required

- Sysmon EID 1 / 4688 (candidate process, parent, image path)
- Sysmon EID 11 (file create — staging writes) and file-read/handle telemetry from EDR
- ETW / EDR directory-enumeration events (`FindFirstFile`/`FindNextFile` bursts) keyed by PID
- Baseline: hunting-wiki list of legitimate bulk-file processes (indexers, backup, AV, DLP)

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint EventCode=11
| eval fn=lower(TargetFilename), ext=lower(mvindex(split(TargetFilename,"."),-1))
| eval doc_ext=if(match(ext,"^(doc|docx|xls|xlsx|ppt|pps|pdf|txt|rtf|jpg|jpeg|png|zip|contract)$"),1,0)
| stats dc(ext) as distinct_exts sum(doc_ext) as doc_reads
        values(ext) as exts dc(TargetFilename) as file_count
        values(mvindex(split(fn,"\\"),-2)) as target_dirs
        by host, Image
| where distinct_exts>=6 AND doc_reads>=10
| eval staging_concentration=round(doc_reads/(mvcount(target_dirs)),1)
| where NOT match(lower(Image),"(searchindexer|searchprotocolhost|backup|defender|mssense|dlp)")
| sort - doc_reads
| table host Image distinct_exts doc_reads file_count target_dirs staging_concentration
```

## Triage guidance

- **Likely malicious:** A non-indexer process that enumerates many extensions across user directories, then reads/copies documents+images into a single staging folder in a short window; staging co-located with `.wav`/screenshot output from HUNT-01; process running under a masqueraded name/path (`iexplore.exe` from a user profile dir).
- **Likely benign:** Windows Search indexer, backup/sync clients, AV/DLP scans, a user opening many files interactively — suppress via the baseline of approved bulk-file processes and account for interactive foreground apps.
- **Pivot next:** If a staging folder of collected documents is confirmed, correlate with HUNT-01 (co-resident capture) and the exfil/C2 lanes; if collection is active, **escalate to incident-response** and preserve the staging directory.

## References

- https://securelist.com/the-madi-campaign-part-i-5/33693/
- https://securelist.com/the-madi-campaign-part-ii/33701/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1005/
