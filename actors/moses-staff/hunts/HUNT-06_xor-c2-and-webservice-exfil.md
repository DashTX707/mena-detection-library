# Hunt: Moses Staff / StrifeWater XOR-encrypted C2 beacon + web-service (Telegram/leak-site) exfil

- **Hypothesis:** If StrifeWater is beaconing and Moses Staff is exfiltrating for its hack-and-leak mission, then plaintext content inspection will fail (the C2 payload is XOR-obfuscated), but the *traffic shape* betrays it: fixed-interval (~20-22s) HTTP beacons to a low-reputation destination with recurring `/RVP/index*.php` URIs and high-entropy request/response bodies, followed by an abnormally large outbound transfer from a server or workstation host to a file-sharing / messaging web service (Telegram, a paste/leak endpoint). The hunt keys on *improper timing/frequency* (regular beacon), *high-entropy* (XOR payload defeats content match), and *volume outlier* (bulk egress to a web service the host never normally uploads to).
- **ATT&CK:**
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control) — XOR-obfuscated C2 traffic
  - T1567 — Exfiltration Over Web Service (exfiltration) — leak-site / Telegram data publication

- **Actor procedure:** Per Cybereason, StrifeWater beacons over HTTP to `techzenspace[.]com` / `87.120.8[.]210` on port 80 using URIs like `/RVP/index8.php` and `/RVP/index3.php` at a ~20-22s default interval, obfuscating traffic with XOR symmetric encryption under a hardcoded key (`9c4arSBr32g6IOni`). Per Check Point/SOCRadar, in line with its hack-and-leak model Moses Staff exfiltrates stolen victim data and publishes it via a dedicated leak website and a Telegram channel to maximize reputational and psychological impact.
- **Why a hunt, not a rule:** The XOR obfuscation defeats signature/content inspection, so there is no payload string to alert on; and web-service uploads (Telegram, cloud drives, pastebins) are legitimate everyday traffic, so a raw "upload to Telegram" rule floods with false positives. The huntable signal is *behavioral*: beacon regularity + high body entropy + a low-reputation or never-before-contacted destination, and — separately — a bulk-egress volume outlier from a host that normally never uploads there. Beacon-jitter analysis and per-host egress baselining are judgement-heavy → hunt. The specific `/RVP/index*.php`-to-known-C2 tuple is an IOC pivot (Level-1, ephemeral), not the durable basis; the durable beacon-shape + entropy analytic, once validated on a scoped enclave, can go to detection-engineering.

## Data sources required

- Proxy / web-gateway logs (URL, host, method, bytes-in/out, timestamp) + firewall/NetFlow for byte volumes
- Zeek/NSM `conn.log` + `http.log` — inter-arrival timing, request-body entropy, destination reputation
- DNS logs — resolution of low-reputation / never-before-seen C2 domains
- Passive DNS / TI reputation feed (as *pivot* on `techzenspace[.]com`, `moses-staff[.]se`, `87.120.8[.]210`)
- Per-host outbound-volume baseline to web-service ASNs (Telegram, file-sharing, paste sites)

## Query starting point

Platform: `SPL / Splunk` — fixed-interval beacon detection + bulk web-service egress outlier

```spl
` (a) StrifeWater-style regular-interval HTTP beacon with recurring /RVP/index*.php URIs `
index=proxy OR index=zeek_http sourcetype=*http*
| eval uri=lower(uri_path)
| where method="GET" AND (like(uri,"/rvp/index%.php") OR match(uri,"/rvp/index\d+\.php"))
| sort 0 src_ip, dest, _time
| streamstats current=f last(_time) as prev by src_ip, dest
| eval delta=_time-prev
| stats count as beacons, avg(delta) as avg_int, stdev(delta) as jitter,
        dc(uri) as uris, values(dest) as dest by src_ip
| where beacons>=20 AND avg_int>=15 AND avg_int<=40 AND jitter<8    ` low jitter = machine beacon `
| sort - beacons

` (b) bulk outbound to a web/messaging service from a host that never normally uploads there `
index=firewall OR index=proxy
| where bytes_out > 0
| eval svc=case(match(dest,"(?i)(t\.me|telegram|api\.telegram|anonfiles|mega\.nz|pastebin|transfer\.sh)"),"webservice",1==1,"other")
| where svc="webservice"
| stats sum(bytes_out) as out_bytes, dc(dest) as dests, min(_time) as first by src_ip, dest
| eventstats avg(out_bytes) as host_avg, stdev(out_bytes) as host_sd by src_ip
| where out_bytes > (host_avg + 4*host_sd) AND out_bytes > 50000000     ` >4 sigma AND >50MB `
| sort - out_bytes
```

## Triage guidance

- **Likely malicious:** a host GET-beaconing every ~20-22s with sub-8s jitter to a low-reputation host, recurring `/RVP/index*.php` URIs, high-entropy request/response bodies (XOR); the beacon originating from a masquerading `calc.exe` (→ HUNT-03/HUNT-05); a server or non-uploading workstation suddenly pushing tens/hundreds of MB to Telegram/a paste or file-sharing endpoint it has never contacted; egress overlapping the leak domains `techzenspace[.]com` / `moses-staff[.]se`.
- **Likely benign / expected:** software update checks, telemetry, RSS/polling agents and monitoring produce regular HTTP intervals — baseline and allowlist their destinations and user-agents; developers and marketing legitimately push large files to cloud drives and messaging apps — baseline per-host egress so a *never-before* bulk upload stands out, not routine ones. Regular beaconing to a *reputable, expected* endpoint is benign; regular beaconing to a low-reputation host with XOR bodies is not.
- **Pivot next:** resolve the beacon process (→ HUNT-03/HUNT-05 to confirm the RAT and extract the XOR key/C2), map every internal host talking to the same destination, and correlate the exfil window against the collection staging (→ HUNT-03) and any destructive precursors (→ HUNT-01). Confirmed C2 + bulk exfil is active hack-and-leak, typically a precursor to destruction → escalate to incident-response-coordinator and block the C2/exfil destinations fleet-wide.

## References

- https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations
- https://socradar.io/blog/dark-web-profile-moses-staff/
- https://attack.mitre.org/techniques/T1573/001/
- https://attack.mitre.org/techniques/T1567/
