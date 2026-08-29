# Hunt: APT33 / Peach Sandstorm covert channels — EagleRelay tunneling, symmetric-encrypted & encoded C2

- **Hypothesis:** If APT33 is running C2 through our environment, then in network/flow and proxy telemetry we should observe its covert-channel tradecraft — EagleRelay tunneling that produces long-lived, low-variance outbound sessions to rare hosting/dynamic-DNS destinations (and the EagleRelay binary on-host), TURNEDUP/POWERTON symmetric-encrypted (AES) web C2 that presents as steady-beacon TLS/HTTP with high-entropy bodies immune to content inspection, and Base64/standard-encoded C2 data in HTTP request/response bodies whose encoded-payload volume and periodicity deviate from any legitimate app — even though each layer individually looks like normal encrypted web traffic.
- **ATT&CK:**
  - T1572 — Protocol Tunneling (command-and-control) — EagleRelay
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control)
  - T1132.001 — Data Encoding: Standard Encoding (command-and-control) — Base64 C2

- **Actor procedure:** As Peach Sandstorm, APT33 used the custom **EagleRelay** tool to tunnel traffic between actor-controlled systems and victim environments, concealing C2 and reaching otherwise unreachable internal systems. Its backdoors (TURNEDUP, POWERTON) beacon over HTTP/HTTPS — often to dynamic-DNS/masquerading domains (`alsalam[.]ddns[.]net`, `boeing[.]servehttp[.]com`) and non-standard ports — layering **symmetric encryption** over the web channel and **Base64/standard encoding** of C2 data so payloads defeat inspection.
- **Why a hunt, not a rule:** Every layer here is engineered to look legitimate — encryption defeats content inspection, tunneling wraps traffic in an allowed protocol, and Base64 is ubiquitous in benign web traffic — so no payload signature is durable, and a rule on "encrypted egress" or "Base64 in HTTP" would bury the SOC. The signal is *behavioral and stacked*: beacon periodicity/jitter, session longevity, bytes-in/out ratio and destination rarity (never-before-seen ASN/dynamic-DNS), correlated with the originating non-browser process. That requires per-host egress baselining and judgement → hunt. The EagleRelay binary hash/name is a Level-1 pivot (the actor changes it); the durable cores — long-lived low-variance non-browser TLS to a rare destination, regular-interval beaconing — can be handed to detection-engineering as beaconing analytics once tuned.

## Data sources required

- Network flow / firewall / Zeek `conn.log` (session duration, bytes ratio, dest IP/port, connection state)
- Proxy / SWG logs (URL, user agent, request/response body size, non-standard ports, `POST` volume)
- DNS logs + passive DNS (dynamic-DNS providers, never-before-resolved domains, low-TTL)
- Sysmon EID 1/3 (process→network: which process owns the egress; is it a browser?)
- ASN / dynamic-DNS / threat-intel enrichment; EDR file inventory for the EagleRelay binary

## Query starting point

Platform: `Splunk SPL` (Zeek conn + proxy) — long-lived low-variance tunnels and periodic encoded beacons to rare destinations

```
index=zeek sourcetype=conn
| eval bytes_ratio = round(orig_bytes / (resp_bytes + 1), 2)
| stats count AS sessions, sum(duration) AS total_dur, avg(duration) AS avg_dur,
        avg(orig_bytes) AS avg_out, stdev(orig_bytes) AS jitter,
        dc(_time) AS beacons values(dest_port) AS ports by src_ip, dest_ip
| where avg_dur > 600 AND jitter < (avg_out * 0.15)          // long-lived + low variance = tunnel/beacon
| join dest_ip [ search index=threatintel (category="dynamic-dns" OR category="hosting" OR asn_rare=1) ]
| table src_ip dest_ip ports sessions avg_dur avg_out jitter beacons
| sort - avg_dur

/* Then attribute the egress to a process (non-browser owner is the tell):
index=sysmon EventCode=3 dest_ip=<hit>
| search Image!="*\\chrome.exe" Image!="*\\msedge.exe" Image!="*\\firefox.exe"
| table _time host Image DestinationIp DestinationPort  */
```

## Triage guidance

- **Likely malicious:** a long-lived, steady-byte, low-jitter outbound session owned by a non-browser process (powershell.exe, a random-named binary, or EagleRelay) to a dynamic-DNS/rare-hosting destination or a non-standard port; regular-interval beaconing with high-entropy or Base64-looking bodies to a never-before-seen domain; egress to the known masquerading domains from the intel pack; the EagleRelay binary present on a host that also shows tunneled sessions.
- **Likely benign / expected:** software-update channels, telemetry/SaaS agents, backup replication and legitimate VPN/RMM all produce long-lived or periodic encrypted sessions — baseline per host and allowlist known SaaS/update ASNs; Base64 in web bodies is normal for many apps. Encryption alone is not evidence — require destination rarity + non-browser owner + periodicity together.
- **Pivot next:** on a hit, pull the owning process and its parent chain (HUNT-05 obfuscated loader, HUNT-04 credential theft), decode any Base64 bodies, and cross-ref the destination against the Golden-SAML / TOR access in HUNT-01 and detection pack T1090.003/T1071.001/T1571. Confirmed active C2 tunnel is a live incident → escalate to IR; hand the beaconing analytic core to detection-engineering.

## References

- https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/
- https://attack.mitre.org/techniques/T1572/
- https://attack.mitre.org/techniques/T1573/001/
- https://attack.mitre.org/techniques/T1132/001/
- https://attack.mitre.org/groups/G0064
