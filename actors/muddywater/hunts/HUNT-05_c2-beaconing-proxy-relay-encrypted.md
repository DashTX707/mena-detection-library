# Hunt: MuddyWater C2 — beaconing, proxy/relay, multi-stage & encrypted channels

- **Hypothesis:** If POWERSTATS/MuddyC2 is active on a host, then network telemetry will show a regular, low-jitter beacon to a small set of destinations — potentially over HTTP with Base64-encoded or AES-encrypted bodies, on non-standard ports (8043/8848), relayed through commercial VPN/proxy or compromised third-party sites, and split across *different* C2 endpoints for tasking vs. exfil — a stack of network anomalies on the same internal host.
- **ATT&CK:**
  - T1071.001 — Application Layer Protocol: Web Protocols (C2)
  - T1090 — Proxy (C2)
  - T1090.002 — Proxy: External Proxy (C2)
  - T1102.002 — Web Service: Bidirectional Communication (C2)
  - T1104 — Multi-Stage Channels (C2)
  - T1132.001 — Data Encoding: Standard Encoding (C2)
  - T1571 — Non-Standard Port (C2)
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (C2)
  - T1041 — Exfiltration Over C2 Channel (exfiltration)
- **Actor procedure:** MuddyWater uses **HTTP for C2**, **Base64-encodes** and **AES-encrypts** C2 content, controls POWERSTATS from **behind a proxy network** and via **go-socks5** variants to bypass firewalls/NAT, relays through **compromised websites victims connect to "randomly,"** uses **OneHub** for bidirectional web-service C2, splits **one C2 for enumeration/log-monitoring and a different C2 for sending data back** (multi-stage), and communicates over **ports 8043 and 8848**.
- **Why a hunt, not a rule:** Encrypted/AES bodies defeat content inspection, relaying through compromised legitimate sites and commercial VPN makes any single destination look benign, and beacon detection is inherently statistical (periodicity, jitter, byte-ratio) rather than signature-based. It needs per-host baselining and cross-flow correlation — exactly the statistical work that belongs in a hunt. (The concrete port-8043/8848 IOC is handed to detection-engineer as a rule; the hunt covers the behavioral shape around it.)

## Data sources required

- Proxy / web-gateway logs (URI, method, bytes in/out, user-agent, JA3/JA3S if available)
- Firewall / NetFlow / Zeek `conn.log` (dest IP, dest port, duration, byte counts)
- DNS logs (resolution of C2 / relay domains)

## Query starting point

Platform: `Splunk SPL`

```
index=network (sourcetype=zeek_conn OR sourcetype=proxy OR sourcetype=firewall)
| eval dport=coalesce(dest_port,id_resp_p)
| bin _time span=1h
| stats count as conns
        avg(duration) as avg_dur
        sum(orig_bytes) as bytes_out sum(resp_bytes) as bytes_in
        dc(_time) as active_hours
        values(dport) as ports dc(dest) as dst_cnt values(dest) as dests
        by src, dest
| eventstats stdev(count) as beacon_jitter avg(count) as beacon_mean by src, dest
| eval regularity=round(beacon_jitter/(beacon_mean+0.01),3)
| eval nonstd_port=if(isnotnull(mvfind(ports,"^(8043|8848)$")),1,0)
| eval exfil_ratio=round(bytes_out/(bytes_in+1),2)
| where (regularity < 0.25 AND conns > 12) OR nonstd_port=1 OR exfil_ratio > 5
| sort regularity
```

## Triage guidance

- **Likely malicious:** Low-jitter beacon (regularity < 0.25) to a rare external destination; traffic to ports **8043/8848**; the *same host* talking to two distinct external endpoints in a tasking-vs-exfil pattern (multi-stage); high outbound/inbound byte ratio (exfil over C2); Base64-looking URIs or connections via commercial VPN egress; destination is a low-reputation or recently-seen site.
- **Likely benign / expected:** Software-update and telemetry beacons (browsers, AV, OS), SaaS keep-alives, monitoring agents — all periodic but to well-known, high-reputation destinations. Baseline and allowlist by destination + process.
- **Pivot next:** Resolve the beaconing process on the endpoint (EDR) → tie to HUNT-01/HUNT-02 lineage; check for RMM/remote-access software on the same host (detection lane); if exfil pattern, correlate with HUNT-06 cloud-storage activity and escalate to IR.

## References

- https://attack.mitre.org/groups/G0069/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a
