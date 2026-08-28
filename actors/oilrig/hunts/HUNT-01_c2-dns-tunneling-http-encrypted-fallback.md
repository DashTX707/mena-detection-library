# Hunt: OilRig C2 — DNS tunneling, HTTP/web, encoded & encrypted channels with fallback

- **Hypothesis:** If an OilRig backdoor (Helminth / ISMAgent / BONDUPDATER / QUADAGENT / POWRUNER) is active on a host, then network telemetry will show a *stack* of C2 anomalies on the same internal source: high-entropy / abnormally long DNS labels with large per-domain subdomain volume (DNS tunneling), or a low-jitter HTTP beacon carrying Base64-encoded bodies, potentially failing over from HTTP to DNS when the primary channel is unreachable (fallback), and possibly asymmetric-encrypted content that defeats inspection.
- **ATT&CK:**
  - T1071.004 — Application Layer Protocol: DNS (command-and-control)
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control)
  - T1132.001 — Data Encoding: Standard Encoding (command-and-control)
  - T1573.002 — Encrypted Channel: Asymmetric Cryptography (command-and-control)
  - T1008 — Fallback Channels (command-and-control)
- **Actor procedure:** OilRig uses DNS for C2 as a *signature* tradecraft across Helminth, ISMAgent, BONDUPDATER and QUADAGENT, including the public `requestbin.net` tunneling service. **ISMAgent explicitly falls back to DNS tunneling when it cannot reach its C2 over HTTP.** A VBS script Base64-encodes the compromised computer name before exfil. PowerExchange and related tooling build encrypted tunnels to C2.
- **Why a hunt, not a rule:** DNS tunneling and beacon detection are statistical (label entropy/length, query volume per parent domain, periodicity, byte ratios), not signature matches; asymmetric-encrypted bodies defeat content inspection; and the HTTP→DNS *fallback* is an architectural trait only visible by correlating two channels on one host. All of this needs per-environment baselining of normal DNS/web volume — unsuitable for a fixed threshold. (Concrete IOCs such as `requestbin.net` are handed to detection-engineer as blocks; the behavioral shape stays here.)

## Data sources required

- Full DNS query logs (query name, record type, response code incl. NXDOMAIN) — frequently under-instrumented; a gap here is itself a finding
- Proxy / web-gateway logs (URI, method, bytes in/out, user-agent, JA3/JA3S)
- Firewall / NetFlow / Zeek `conn.log` + `dns.log` (dest IP/port, duration, byte counts)

## Query starting point

Platform: `Splunk SPL`

```
index=network sourcetype=zeek_dns
| eval sub=mvindex(split(query,"."),0)
| eval sublen=len(sub)
| eval ent=round(len(replace(sub,"[^a-fA-F0-9]",""))/(len(sub)+0.01),2)
| eval parent=mvindex(split(query,"."),-2)."." . mvindex(split(query,"."),-1)
| bin _time span=1h
| stats count as q dc(query) as uniq_sub avg(sublen) as avg_len max(sublen) as max_len
        sum(eval(rcode_name="NXDOMAIN")) as nxdomain by _time, src, parent
| where (uniq_sub > 200 AND avg_len > 30) OR max_len > 50 OR nxdomain > 50
| sort - uniq_sub
```

## Triage guidance

- **Likely malicious:** hundreds of unique high-entropy subdomains under one parent domain from a single host; average label length > 30 chars; TXT/NULL/CNAME record types dominating; a host that beacons over HTTP then shifts to heavy DNS to the same registrable domain within the hour (fallback); Base64-looking URIs with steady inter-arrival timing; low-reputation or newly-seen authoritative domain.
- **Likely benign / expected:** CDN, anti-spam (DNSBL), telemetry and cloud-security agents that legitimately issue long/encoded subdomains (e.g. `*.avts.*`, `*.trendmicro.*`); DNS load-balancers. Baseline and allowlist by parent domain + process.
- **Pivot next:** resolve the querying process on the endpoint (EDR) → tie to macro/script lineage (HUNT-09); check for encoding/decoding on the same host (certutil/FromBase64String, detection lane); if exfil-shaped, correlate with Exchange/OWA activity (detection lane T1048.003) and escalate to IR.

## References

- https://attack.mitre.org/groups/G0049/
- https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
