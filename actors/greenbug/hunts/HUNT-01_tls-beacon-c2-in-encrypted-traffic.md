# Hunt: Greenbug — TLS-wrapped Cobalt Strike / Covenant beacons hiding in encrypted traffic

- **Hypothesis:** If Greenbug's post-exploitation frameworks (Cobalt Strike Beacon, Covenant) are live on our estate, then their C2 content is opaque TLS that payload inspection cannot read — but the *shape* of the flow still betrays it: a small set of internal hosts holding long-lived, regularly-timed (jittered-but-periodic) HTTPS/TLS sessions to a raw-IP or thin-reputation external endpoint, frequently on a **non-standard port** (Greenbug used 445/1003/1131/8081 for HTTP staging and reuses odd ports for TLS C2), presenting a **repeating/known-bad JA3/JA3S fingerprint** or a **self-signed / default-Cobalt-Strike certificate**, with steady low-variance bytes-out per connection consistent with beaconing rather than human browsing. No single one of those is the finding; a host stacking beacon-timing regularity + rare-JA3 + odd-port + thin-reputation destination is.
- **ATT&CK:**
  - T1573.002 — Encrypted Channel: Asymmetric Cryptography (command-and-control) — the core of this hunt: Cobalt Strike/Covenant tunnel beacon content over TLS to conceal it; hunt the flow metadata (JA3/JA3S, cert, timing) not the payload.
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — the beacon rides HTTPS to blend with normal web traffic; proxy/SNI metadata is the pivot surface.
  - T1571 — Non-Standard Port (command-and-control) — Greenbug C2/staging on 445/1003/1131/8081; protocol-vs-port mismatch (TLS on an atypical port) narrows the candidate set.

- **Actor procedure:** In the South Asia telecom intrusions Greenbug moved past its PowerShell/DNS ISMDOOR channel to off-the-shelf frameworks — the Covenant .NET C2 (GRUNTStager.hta), Cobalt Strike Beacon and Metasploit — for interactive post-exploitation. These stage over HTTP on odd ports (95.179.177.157:445/:8081, 185.205.210.46:1003/:1131) and then run their operator C2 inside TLS so the beacon traffic reads as ordinary HTTPS. The tradecraft goal is dwell: persistent, low-profile credential theft that survives casual netflow review because the content is encrypted and the destination looks like "just another HTTPS site."

- **Why a hunt, not a rule:** TLS content is opaque by design, so there is nothing in the payload to alert on, and every single metadata signal here is individually noisy — plenty of legitimate software beacons on a fixed interval (telemetry, update checks, EDR itself), plenty of SaaS lives on odd ports, and JA3 collides across unrelated TLS stacks. A standalone rule on any one of these drowns in false positives. The finding is the *correlation*: the same internal host stacking timing-regularity AND a rare/known-CS JA3 AND an odd-port/thin-reputation destination — a judgement call that fuses several weak signals against a baseline. If a durable, precise observable falls out (e.g. a specific JA3/JA3S pair to a confirmed-malicious cert on a port your estate never legitimately uses), hand *that* to detection-engineering as a scoped analytic; do not try to alert on "TLS looks beacon-y."

## Data sources required

- Zeek/Suricata (or NDR) `ssl.log` / TLS metadata: JA3, JA3S, SNI, certificate subject/issuer, validity, self-signed flag, destination IP:port
- Zeek `conn.log` / firewall / netflow: per-flow bytes-out, duration, connection cadence to external destinations (for beacon-timing analytics)
- Proxy / SSL-inspection logs (where TLS is terminated): full URL, user-agent, destination reputation
- Threat-intel enrichment: IP/domain/ASN reputation, first-seen/registration age, known Cobalt Strike default-cert and team-server JA3S corpora

## Query starting point

Platform: `KQL / Microsoft Sentinel` (Zeek/Corelight or firewall TLS logs normalized into a `TlsEvents`-style table)

```kusto
// Beacon-shaped TLS: per src/dst, regular cadence + low byte-variance + odd port + rare JA3
let lookback = 14d;
let knownGoodJa3 = _GetWatchlist('approved_ja3');            // EDR, update agents, sanctioned SaaS
let corp = _GetWatchlist('corp_egress_dns_names');           // known-good SNI allowlist
TlsEvents
| where TimeGenerated > ago(lookback)
| where DestinationIp !startswith "10." and DestinationIp !startswith "192.168."
| extend oddPort = DestinationPort !in (443, 8443)
| summarize conns = count(),
            intervals = make_list(TimeGenerated, 500),
            avgBytesOut = avg(SentBytes),
            stdevBytesOut = stdev(SentBytes),
            ja3set = make_set(Ja3, 10), ja3sset = make_set(Ja3s, 10),
            sniset = make_set(Sni, 20),
            selfSigned = anyif(1, CertSelfSigned == true),
            oddPortHit = anyif(DestinationPort, oddPort)
        by SourceIp, DestinationIp, DestinationPort
| where conns >= 24                                          // sustained, not a one-off
// regular cadence: low coefficient-of-variation between consecutive connection times
| extend deltas = array_iff(array_length(intervals) > 2, intervals, dynamic([]))
| where stdevBytesOut < (avgBytesOut * 0.25)                 // beacon = uniform payload size
| where array_length(set_difference(ja3set, knownGoodJa3)) > 0   // JA3 not on approved list
| extend rawIpDest = DestinationIp                           // raw-IP dest w/ no SNI is a strong pivot
| where isempty(tostring(sniset)) or oddPortHit != 0 or selfSigned == 1
// stack the anomalies — score and surface the top offenders for analyst review
| extend anomalyStack = (oddPortHit != 0) + (selfSigned == 1) + (array_length(sniset) == 0)
| where anomalyStack >= 2
| project SourceIp, DestinationIp, DestinationPort, conns, avgBytesOut, stdevBytesOut,
          ja3set, ja3sset, sniset, selfSigned, anomalyStack
| order by anomalyStack desc, conns desc
```

For beacon-interval regularity specifically, pivot the shortlisted `SourceIp/DestinationIp` pairs into a periodicity check (delta-between-connections FFT or coefficient-of-variation < ~0.1) — a near-constant inter-arrival time with small jitter is the timing anomaly that turns a "long TLS session" into "beacon."

## Triage guidance

- **Likely malicious:** an internal host holding a sustained, regularly-timed TLS session to a **raw IP with no SNI** (or a days-old / thin-reputation domain) on a **non-standard port**, presenting a **JA3/JA3S that matches a Cobalt Strike default or a known team-server fingerprint**, and/or a **self-signed or default-Cobalt-Strike certificate**, with uniform bytes-out per connection. Extra weight if the same host also shows Greenbug on-victim tells from the detection lane (hh.exe→PowerShell, GRUNTStager.hta, Mimikatz, Plink/comms.exe tunneling) or ever touched the known Greenbug staging IPs 95.179.177.157 / 185.205.210.46.
- **Likely benign / expected:** EDR agents, OS/app update services, telemetry SDKs and sanctioned SaaS all beacon on fixed intervals over TLS with stable JA3 — baseline and allowlist their JA3/JA3S and destinations first. Corporate SaaS legitimately uses 8443 and occasionally other ports; CDNs rotate certs; a valid CA-signed cert to a well-aged, high-reputation domain is not this. A single anomaly (odd port alone, or regular timing alone) is noise; require the stack.
- **Pivot next:** on a stacked hit, pull the host's process/parent telemetry for the beaconing PID (is the TLS owner powershell.exe, an .hta host, rundll32, or an unsigned binary in AppData?), sweep the destination IP/ASN/cert across all hosts (retro-hunt — feeds HUNT-02 staging-infra tracking), and check for co-located credential access (Mimikatz/LSASS, web.config decryption). If the beacon owner is a masqueraded or unsigned process and the destination is confirmed C2, treat as a live intrusion and escalate to incident-response-coordinator. If a precise JA3S+cert+port tuple is confirmed malicious, hand it to detection-engineering.

## References

- https://www.security.com/threat-intelligence/greenbug-espionage-telco-south-asia
- https://www.security.com/threat-intelligence/shamoon-attacks-mount-middle-east
- https://www.netscout.com/blog/asert/greenbugs-dns-isms
- https://attack.mitre.org/techniques/T1573/002/
- https://attack.mitre.org/techniques/T1071/001/
- https://attack.mitre.org/techniques/T1571/
