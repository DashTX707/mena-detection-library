# Hunt: Periodic ICMP connectivity checks to a fixed external host from a non-network process

- **Hypothesis:** If a Madi-style implant is checking C2 availability, then a workstation will emit regular ICMP echo requests to a single fixed external IP — not name-resolved, not part of normal monitoring — originating from a user-space process rather than a network/monitoring tool, so egress/flow logs will show low-volume, periodic ICMP to one hard-coded external address with no preceding DNS lookup. Occasional ICMP is benign; periodic ICMP to one hard-coded external host from a non-network process is the finding.
- **ATT&CK:**
  - T1095 — Non-Application Layer Protocol (command-and-control)
- **Actor procedure:** Beyond HTTP, Madi-infected hosts performed ICMP ping checks against the C2 servers as a connectivity/availability probe, and later downloaders hard-coded C2 IP addresses directly, avoiding DNS name resolution — so the ICMP target appears with no corresponding DNS query.
- **Why a hunt, not a rule:** ICMP is ubiquitous (monitoring, path MTU, connectivity tests) so alerting on ICMP is untenable, and the specific historical IPs are dead. The durable signal is behavioural: *periodicity + fixed external destination + absence of a DNS resolution + a user-space rather than network-tooling source process* — an unexpected-relationship/timing anomaly that requires baselining normal ICMP egress, not a static IP block.

## Data sources required

- Firewall / NetFlow / Zeek `conn.log` (ICMP records: src, dst, timing, volume)
- Zeek `dns.log` (to confirm the destination IP was reached without a prior name lookup)
- Sysmon EID 22 (DNS query) and EID 3 (network connection) to attribute ICMP-adjacent activity to a source process
- Baseline: hunting-wiki list of approved ICMP sources (monitoring servers, gateways)

## Query starting point

Platform: `Splunk SPL`

```
index=network (sourcetype=zeek_conn OR sourcetype=*flow*) proto=icmp
| where NOT cidrmatch("10.0.0.0/8",dst) AND NOT cidrmatch("172.16.0.0/12",dst)
        AND NOT cidrmatch("192.168.0.0/16",dst)
| bin _time span=1h
| stats count as icmp_pkts dc(_time) as active_hours
        avg(orig_bytes) as avg_bytes by src, dst
| where active_hours>=6 AND icmp_pkts<500
| join type=left src dst [
    search index=network sourcetype=zeek_dns
    | eval answer=answers | fields query answer
    | rename answer as dst | stats values(query) as resolved_names by dst ]
| where isnull(resolved_names)
| eval src_not_monitoring=if(match(src,"^(10\.0\.0\.5|10\.0\.0\.6)$"),0,1)
| where src_not_monitoring=1
| sort - active_hours
| table src dst icmp_pkts active_hours avg_bytes resolved_names
```

## Triage guidance

- **Likely malicious:** A workstation sending low-volume, periodic ICMP to one fixed external IP across many hours with no DNS resolution for that address; the ICMP source host also shows collection/staging behaviour (HUNT-01/HUNT-02); ICMP source process is a masqueraded user-space binary.
- **Likely benign:** Monitoring/NMS servers, load balancers, VPN/keepalive probes, path-MTU discovery — suppress approved ICMP sources via baseline. Bursty high-volume ICMP is more likely diagnostics than a beacon.
- **Pivot next:** Attribute the ICMP to a source process (Sysmon EID 3); if it is the same host/process flagged in HUNT-01/HUNT-02, treat as C2 connectivity-checking and **escalate to incident-response**; hunt the paired HTTP exfil channel (detection lane, T1071.001/T1041).

## References

- https://securelist.com/the-madi-campaign-part-i-5/33693/
- https://securelist.com/the-madi-campaign-part-ii/33701/
- https://attack.mitre.org/techniques/T1095/
