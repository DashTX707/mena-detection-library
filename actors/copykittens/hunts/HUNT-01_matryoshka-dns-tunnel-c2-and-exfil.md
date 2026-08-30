# Hunt: CopyKittens — Matryoshka DNS-tunnel C2 and DNS-based exfiltration blending with legitimate nameserver traffic (FLAGSHIP)

- **Hypothesis:** If CopyKittens' Matryoshka RAT is resident, then the signature tell is not a clean payload on disk but a *sustained, structured DNS conversation* to a small set of attacker nameservers (`nameserver.win`, `dnsserv.host`, `nsserver.host`, `gtld-servers.services/.solutions/.zone`, `gsvr-static.co` staged subdomains) that is deliberately shaped to look like CDN/nameserver traffic — many unique, long, high-entropy subdomain labels under one or two second-level domains, TXT/NULL/CNAME record types out of proportion to A/AAAA, and a query cadence with a machine-like beacon rhythm rather than human browsing. The exfil variant tunnels stolen files/keystrokes/screenshots *out* inside the query labels themselves, so the same domain shows an outbound-heavy label-length distribution. Neither long labels alone nor volume alone is the finding; a single internal host stacking high-entropy-labels **and** low-diversity-answer **and** beacon-periodicity against one apex is. Runtime decode of the tunneled blobs (T1140) is the in-memory companion signal — little discrete artifact, so it is corroborated by the implant's process lineage (rundll32-hosted DLL) rather than a decode event of its own.
- **ATT&CK:**
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — Matryoshka decodes DNS-tunneled commands and staged payloads in memory at runtime; hunted via process-lineage correlation to the DNS-talking implant, not a discrete decode artifact.
  - T1071.004 — Application Layer Protocol: DNS (command-and-control) — *context, detection-lane* — the DNS C2 channel this hunt walks; cited to frame the tunnel behavior, alerting lives in the detection pack.
  - T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol (exfiltration) — *context, detection-lane* — DNS-tunnel exfil that blends with name resolution; framed here, alerting in the detection pack.

- **Actor procedure:** Matryoshka (v1/v2), CopyKittens' self-developed RAT, uses DNS as its primary C2 and as an exfiltration channel. Commands and stolen data are encoded into DNS queries/responses to attacker-run nameservers. The domains are chosen to masquerade as generic DNS/CDN infrastructure (`gtld-servers.*`, `nameserver.win`, `dnsserv.host`) so that a wall of odd DNS traffic reads as "some CDN doing CDN things." Collected artifacts (keystrokes, screenshots, files — see HUNT-04) and beacon check-ins ride the same channel, so a single implanted host produces both inbound-command and outbound-data DNS patterns against the same apex. The RAT decodes the tunneled content in memory (T1140), typically inside a rundll32-hosted DLL component (detection pack T1218.011).
- **Why a hunt, not a rule:** Well-tuned DNS tunneling that mimics nameserver traffic is exactly the case where a static threshold rule ("label length > N" or "queries/hour > M") either misses the tuned-low variant or drowns SOC in CDN, telemetry-SDK, antivirus-cloud-lookup, and DNS-security-vendor false positives. The finding is the *co-occurrence* of several weak DNS anomalies on the **same host + same apex**, judged against that host's own baseline and against the known-benign high-volume-DNS inventory — correlation and analyst judgement, not a single observable. If a specific apex is confirmed malicious and its query-shape is stable, hand the "host beacons to apex X with entropy>H and answer-diversity<D" tuple to detection-engineering as a scoped analytic keyed on the durable label-structure (a Summiting Level-4 behavioral observable), not on the IP/domain string (Level-1) which the actor rotates freely.

## Data sources required

- DNS resolver/query logs (Windows DNS Analytical, Sysmon Event ID 22, Zeek `dns.log`, Umbrella/DNS-firewall) — query name, record type, answer, per-host source
- NetFlow / firewall egress to port 53 (and DoH/DoT 443/853) for volume corroboration where query logging is incomplete
- EDR process-network telemetry to attribute the DNS talker to a process (rundll32-hosted DLL, unexpected DNS-issuing process)
- Baseline inventory of legitimate high-volume-DNS assets (SDN/CDN edge, security appliances, DNS forwarders) to suppress known talkers

## Query starting point

Platform: `Splunk SPL` — stack entropy, answer-diversity and beacon-rhythm anomalies per host+apex

```spl
index=dns sourcetype=stream:dns OR sourcetype=sysmon EventCode=22
| eval apex=mvindex(split(query,"."), -2) . "." . mvindex(split(query,"."), -1)
| eval label=mvindex(split(query,"."),0)
| eval label_len=len(label)
``` (compute Shannon entropy of the leftmost label via a lookup/macro `dns_entropy(label)`) ```
| eval label_entropy=dns_entropy(label)
| stats count as queries
        dc(query) as unique_names
        dc(answer) as unique_answers
        avg(label_len) as avg_label_len
        max(label_len) as max_label_len
        avg(label_entropy) as avg_entropy
        values(record_type) as rrtypes
        by src_ip apex
| eval answer_diversity=round(unique_answers/queries,3)
| where unique_names > 200 AND avg_label_len > 25 AND avg_entropy > 3.5 AND answer_diversity < 0.05
| search NOT [ inputlookup benign_highvol_dns_apex.csv | fields apex ]
| sort - unique_names
```
Corroborate survivors with a second pass for beacon periodicity (regular inter-query delta, low jitter) and for a TXT/NULL/CNAME share far above the environment norm; then pivot to EDR to name the DNS-issuing process.

## Triage guidance

- **Likely malicious:** one internal host generating hundreds/thousands of unique high-entropy subdomains under a single non-CDN apex, near-zero answer diversity, a beacon-like cadence, and a TXT/NULL-heavy record mix — especially when the DNS talker is `rundll32.exe` hosting a DLL from a user/temp path (cross-ref detection pack T1218.011) or the apex resembles `gtld-servers.*`/`nameserver.win`/`dnsserv.host`. Outbound-heavy label-length distribution on that apex indicates active exfil (T1048.003).
- **Likely benign / expected:** CDNs, anti-malware cloud-lookup (SmartScreen, AV reputation), telemetry SDKs and some DNS-security products legitimately emit many unique, long, high-entropy labels — baseline and suppress these apexes and their known source hosts; DNS load-balancers/forwarders aggregate the whole estate's queries and will top the volume list (analyze by original client, not the forwarder). A single long label or one TXT lookup is normal.
- **Pivot next:** if a host stacks the anomalies against a suspicious apex, treat as active Matryoshka C2 — pivot to the process lineage (rundll32/DLL, autostart persistence — detection pack T1547.001/T1053.005), pull the implant for the decode routine (T1140) and keystroke/screenshot collection (HUNT-04), and if data-bearing outbound labels confirm exfil, escalate to incident-response-coordinator. Hand the stable host+apex+shape tuple to detection-engineering for a scoped analytic.

## References

- https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf
- https://www.clearskysec.com/copykitten-jpost/
- https://attack.mitre.org/techniques/T1140/
- https://attack.mitre.org/techniques/T1071/004/
- https://attack.mitre.org/techniques/T1048/003/
