# Hunt: Encrypted staging, C2 tasking fetch, and exfiltration over the C2 channel

- **Hypothesis:** If a Domestic Kitten implant is exfiltrating, then a collection burst will be followed by AES-encrypted staging (a high-entropy archive written to a temp/AppData path) and by egress that both pulls tasking/config and uploads over the same HTTP C2 — with FurBall's characteristic fixed ~10-second beacon to rotating server-side PHP paths — producing an improper-timing (fixed-interval) + high-entropy + unexpected-relationship anomaly stack on one host.
- **ATT&CK:**
  - T1560 — Archive Collected Data (collection)
  - T1105 — Ingress Tool Transfer (command-and-control)
  - T1041 — Exfiltration Over C2 Channel (exfiltration)
- **Actor procedure:** The Python info-stealer AES-encrypts collected data via `pyAesCrypt` with a hard-coded password before upload, and the Rampant Kitten Android backdoor likewise AES-encrypts before FTPS. FurBall retrieves configuration/command updates from its C2 (an operator-added capability on top of the KidLogger base), letting operators re-point and re-task devices post-deployment (T1105), and uploads captured SMS, call recordings, media and location back over the same HTTP channel it polls for tasking, beaconing roughly every 10 seconds to obfuscated, periodically-changed PHP URIs (T1041).
- **Why a hunt, not a rule:** Encrypted archiving blends with legitimate backup/compression, and the config-fetch/exfil ride the normal HTTP channel, so no single event is alertable — the C2 domains rotate (IOC-level, Level 1) and the exact PHP paths change by design. The durable hunt is the behavioral shape: a fixed-interval beacon with balanced small-request/larger-upload asymmetry, plus a high-entropy archive appearing right after a collection burst — stacked per host. A stable fixed-interval-beacon analytic can later be handed to detection-engineering.

## Data sources required

- Proxy / firewall egress logs (URL/host, method, request+response bytes, timestamp, user-agent, JA3/TLS)
- DNS resolver logs (repeated resolution of C2 hosts; NXDOMAIN churn from rotating paths)
- EDR / file-write events (new high-entropy archive files in temp/AppData; `pyAesCrypt`/PyInstaller artifacts)
- Mobile-network egress where FurBall devices are visible

## Query starting point

Platform: `Splunk SPL`

```
index=proxy OR index=firewall
| eval host_dom=lower(dest_host)
| `comment("fixed-interval beacon + upload asymmetry to a small set of external hosts")`
| bin _time span=1s
| streamstats current=f last(_time) as prev by src_ip, host_dom
| eval delta=_time-prev
| stats count as hits
        avg(delta) as avg_interval stdev(delta) as jitter
        sum(bytes_out) as up sum(bytes_in) as down
        dc(uri_path) as distinct_paths values(dest_host) as hosts
        by src_ip, host_dom
| eval up_down_ratio=round(up/(down+1),2)
| `comment("~10s regular beacon (low jitter), path churn, net upload")`
| where hits > 30 AND avg_interval < 20 AND jitter < 4
        AND (distinct_paths > 5 OR up_down_ratio > 2)
| sort - hits
| join type=left src_ip [
    search index=edr EventCode=11 (file_extension="aes" OR file_extension="7z" OR file_entropy>7.5)
      (TargetFilename="*\\Temp\\*" OR TargetFilename="*\\AppData\\*")
    | stats values(TargetFilename) as staged_archives by src_ip ]
```

## Triage guidance

- **Likely malicious:** A host beaconing at a near-fixed ~10s cadence with low jitter to an external host, churning URI/PHP paths, net-uploading more than it downloads, with a fresh high-entropy `.aes`/archive written to Temp/AppData just before the uploads; resolution of the named FurBall/Rampant Kitten C2 domains is a strong (but IOC-level) confirmer, not the basis of the hunt.
- **Likely benign:** Software-update pollers, telemetry/RUM beacons, and cloud-backup clients with regular cadence — but these use signed CDNs, stable paths, and download-heavy ratios. Baseline the host's normal periodic egress and exclude sanctioned updaters/backup.
- **Pivot next:** If the beacon + staged-archive stack confirms, capture the archive and PCAP, block the C2 at egress, and pivot to HUNT-04/HUNT-03 for the collection source feeding it. Hand the fixed-interval-beacon analytic to detection-engineering; confirmed C2 is an incident — **escalate to incident-response**.

## References

- https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/
- https://research.checkpoint.com/2020/rampant-kitten-an-iranian-espionage-campaign/
- https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/
- https://attack.mitre.org/techniques/T1560/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1041/
