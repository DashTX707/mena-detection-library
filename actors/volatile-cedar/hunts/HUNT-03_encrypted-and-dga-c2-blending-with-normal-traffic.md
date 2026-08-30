# Hunt: Volatile Cedar — encrypted / DGA C2 that blends with normal web traffic

- **Hypothesis:** If an Explosive v4 implant is live in our estate, then because its C2 is encrypted (defeating content inspection) the tell is not the *payload* but the *metadata*: a compromised host — typically an internet-facing web/app server that has no business being a chatty HTTP(S) client — emitting regular, low-variance beacons (fixed interval + near-constant small request size) over 443, punctuated by the fallback signature when its hardcoded static C2 is unreachable: a *burst of NXDOMAIN responses followed by successful resolution of high-entropy, algorithmically-generated domains*. The finding stacks two anomalies on the same host — machine-like beacon regularity AND a DGA/NXDOMAIN fallback burst — because either alone is thin (health-checks beat regularly; a single NXDOMAIN burst can be a typo or a dead CDN), but a server-role host doing both is Explosive re-homing to its dynamic update servers.
- **ATT&CK:**
  - T1573 — Encrypted Channel (command-and-control) — Explosive v4 encrypts C2, so detection shifts from content to beacon-cadence + destination metadata
  - T1008 — Fallback Channels (command-and-control) — static-C2-unreachable triggers a fallback that manifests as failed-connection bursts before algorithmic-domain resolution
  - T1568.002 — Dynamic Resolution: Domain Generation Algorithms (command-and-control) — high-entropy DGA domains cycled as dynamic update servers when hardcoded C2 is down
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — HTTP(S) beaconing to static C2 with the fixed `/micro/data/index.php?micro=` URI structure

- **Actor procedure:** Explosive beacons to hardcoded static updater C2 over HTTP(S) — Kaspersky observed check-ins to `edortntexplore[.]info` at `/micro/data/index.php?micro=4` on port 443 — and, per ClearSky, Explosive v4 *encrypts* its C2 communications as an evasion measure. When the implant cannot reach its hardcoded static C2 it falls back to a DGA, cycling through algorithmically-generated candidate domains to relocate live infrastructure (Kaspersky sinkholed exactly this DGA pool). The result is a normally-quiet, regular primary channel with a noisy DGA/NXDOMAIN fallback under disruption.
- **Why a hunt, not a rule:** The encryption deliberately blinds content inspection, and generic beacon-regularity or DGA detectors are notoriously noisy — legitimate telemetry agents, health checks, NTP, and CDN failover all produce regular beacons or NXDOMAIN bursts. A standalone alert on "regular 443 beacon" or "high-entropy domain" would bury an analyst. The signal only emerges from *stacking* the anomalies on a host whose role makes outbound beaconing abnormal (a web server acting as a client) and correlating cadence with a fallback burst — that baselining and multi-signal correlation is hunt work. If a durable per-host observable falls out (e.g., the exact Explosive URI regex to a non-allow-listed destination), hand that to detection-engineering.

## Data sources required

- Proxy / TLS-metadata logs (destination, SNI, JA3/JA3S, bytes-out, request cadence) — content need not be decrypted
- DNS resolver logs including response code (to catch NXDOMAIN bursts) and queried-name entropy
- NetFlow / firewall egress for periodicity and byte-size variance per (src host → dst)
- Asset inventory / CMDB to flag which internal hosts are *server-role* (should not be beaconing outbound)

## Query starting point

Platform: `Splunk SPL` — compute per-host beacon regularity and fold in a DGA/NXDOMAIN fallback burst on the same host.

```spl
index=proxy earliest=-14d
| bin _time span=1m
| stats count as reqs values(bytes_out) as bo by src_ip dest dest_port _time
| stats count as intervals avg(reqs) as avg_reqs
        stdev(reqs) as jitter dc(_time) as active_minutes
        by src_ip dest dest_port
| where active_minutes>=60 AND jitter<1.0 AND avg_reqs<=5           `` low-jitter, low-volume = machine beacon ``
| eval beacon_score=round(active_minutes/(jitter+0.1),1)
| join type=left src_ip [
    search index=dns earliest=-14d (reply_code=NXDOMAIN OR reply_code=3)
    | eval qlen=len(query), vowels=mvcount(split(lower(query),"a"))+mvcount(split(lower(query),"e"))
    | eval entropy_proxy=qlen-vowels                                 `` crude high-entropy proxy ``
    | stats count as nxdomain_burst avg(entropy_proxy) as avg_entropy by src_ip
    | where nxdomain_burst>=20 AND avg_entropy>=8 ]
| where isnotnull(nxdomain_burst)                                    `` stack: beacon AND DGA fallback ``
| table src_ip dest dest_port beacon_score jitter active_minutes nxdomain_burst avg_entropy
| sort - beacon_score
```

## Triage guidance

- **Likely malicious:** a *server-role* host (internet-facing Confluence/Jira/Oracle/IIS box) that beacons with near-zero jitter over 443 to a non-allow-listed destination AND shows an NXDOMAIN burst resolving into high-entropy domains; a beacon whose URI matches the Explosive `/micro/data/index.php?micro=` structure; the same host appearing in the infrastructure hunt (HUNT-02) or web-shell detection lane. Two stacked anomalies on a host that should never be an outbound HTTP client is the finding.
- **Likely benign / expected:** endpoint/telemetry agents (EDR, SIEM forwarders, APM), OS/AV updaters and health-check pollers legitimately beacon regularly — baseline and allow-list them by process/destination; misconfigured clients, dead CDNs, and captive-portal probing generate benign NXDOMAIN bursts; DGA-style names also appear in ad-tech and malware-sandbox traffic. Workstations beaconing is far less interesting than servers beaconing.
- **Pivot next:** confirm the process/parent on the beaconing host via EDR (is the caller a web/app-server child or an unsigned modular binary? cross-ref detection pack T1129/T1574.001); resolve the DGA domains and push them to passive-DNS tracking (HUNT-02); if the destination or URI matches known Explosive infrastructure, treat as confirmed C2 and escalate to incident-response-coordinator. Hand the durable URI/destination observable to detection-engineering.

## References

- https://securelist.com/sinkholing-volatile-cedar-dga-infrastructure/69421/
- https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
- https://blog.checkpoint.com/security/volatilecedar/
- https://attack.mitre.org/techniques/T1573/
- https://attack.mitre.org/techniques/T1008/
- https://attack.mitre.org/techniques/T1568/002/
- https://attack.mitre.org/techniques/T1071/001/
