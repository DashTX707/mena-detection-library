# Hunt: RAT-driven anti-forensic file deletion

- **Hypothesis:** If a Group5 RAT operator cleaned up on an infected host, then file-deletion audit events will cluster under a single suspicious process lineage — a masqueraded/unsigned RAT process (e.g. `dwm.exe` from a non-`System32` path, `putty.exe` from a download/temp folder, or a decoy dropper) deleting its own dropper, staged tooling, or captured-data staging files shortly after execution or C2 activity — an unexpected-relationship (a non-shell, non-installer process issuing deletes) stacked with improper timing (deletes immediately following download/first-run or a C2 session).
- **ATT&CK:**
  - T1070.004 — Indicator Removal: File Deletion (stealth)
- **Actor procedure:** Group5's njRAT and NanoCore RATs provided remote file-deletion, letting operators remove files — including their own droppers and artifacts — from infected Syrian-opposition systems. Combined with the multi-stage delivery (first-stage `putty.exe` fetching NanoCore as `dwm.exe`), this leaves a window where the first stage or decoy is deleted after the second stage installs.
- **Why a hunt, not a rule:** Files are deleted constantly on healthy systems, so a standing "file deleted" rule is pure noise. The hunt value is in *correlating deletions to a suspicious process lineage and to timing* — self-deletion of a just-written executable, deletion of a masqueraded binary's own image, or removal of staged capture files right after a C2 session. That correlation requires process-to-file-event stitching and per-host baselining of what normally deletes executables, which is analyst-driven hunting, not a precise alert.

## Data sources required

- Sysmon EID 23 / 26 (FileDelete / FileDeleteDetected) with initiating process image and hashes
- Windows Security 4663 (object access — delete) on user-writable and temp/download paths, where object auditing is enabled
- Sysmon EID 1 / 11 (process creation and prior file-write of the same path, to reconstruct write→execute→delete timing)
- Sysmon EID 3 (network) to correlate deletions occurring around C2 sessions

## Query starting point

Platform: `Splunk SPL`

```
index=edr (EventCode=23 OR EventCode=26 OR event_type="file_delete")
| eval deleted=lower(TargetFilename), proc=lower(Image), ppath=lower(coalesce(ProcessPath,Image))
| where match(deleted,"\.(exe|dll|scr|apk|tmp)$")
        OR match(deleted,"(temp|appdata\\\\local\\\\temp|downloads)\\\\")
| eval self_delete=if(deleted==proc,1,0)
| eval masq_proc=if(
      (match(proc,"\\\\dwm\.exe$")   AND NOT match(ppath,"\\\\windows\\\\system32\\\\dwm\.exe$")) OR
      (match(proc,"\\\\putty\.exe$")  AND match(ppath,"(temp|downloads|appdata)")) OR
      signature_status!="Valid", 1, 0)
| where self_delete=1 OR masq_proc=1
| join type=left process_guid
    [ search index=edr sourcetype=*network* event_type="connect"
      | stats values(dest_ip) as c2 dc(dest_ip) as c2_count by process_guid ]
| stats count values(deleted) as deleted_files values(proc) as process
        values(c2) as c2_ips max(self_delete) as self_delete max(masq_proc) as masq
        by host, process_guid
| where self_delete=1 OR masq=1 OR isnotnull(c2_ips)
| sort - count
```

## Triage guidance

- **Likely malicious:** A process deleting its own on-disk image (self-delete) shortly after first execution; a masqueraded binary (`dwm.exe` outside `System32`, `putty.exe` from a download/temp path) deleting executables or staged files; a burst of deletes in a user-writable path timed right after a payload download or a C2 session; deletion of a first-stage dropper immediately after a second stage is written.
- **Likely benign / expected:** Installers and updaters cleaning their own temp files; browser/download-manager temp churn; disk-cleanup and AV quarantine deletions; developer build artifacts. Baseline which processes normally delete executables per host and exclude signed installers under change control.
- **Pivot next:** Tie the deleting process back to HUNT-02 (PAC Crypt / RAT family) and HUNT-03 (surveillance behaviors) on the same host; recover deleted artifacts from backups/USN journal/`$MFT` for the RAT sample. Confirmed RAT self-cleanup on a live host indicates active compromise — **escalate to incident-response** and preserve volatile evidence before further deletion.

## References

- https://citizenlab.ca/2016/08/group5-syria/
- https://attack.mitre.org/groups/G0043/
- https://attack.mitre.org/techniques/T1070/004/
