# Hunt: RAT exfiltration over the DDNS command-and-control channel

- **Hypothesis:** If a SpyNote/SpyMax handset is exfiltrating collected data to OilAlpha, then network/flow telemetry (where mobile traffic transits the corporate WiFi/VPN) will show a device holding a persistent outbound session to a DDNS host on a high non-standard port (44414/44449) with an upload-heavy byte ratio and periodic beacon cadence — stacking a volume-outlier anomaly (sustained outbound bytes to one external host) on an unexpected-relationship anomaly (a phone talking to a free-DDNS endpoint over a 5-digit port).
- **ATT&CK:**
  - T1041 — Exfiltration Over C2 Channel (exfiltration)
- **Actor procedure:** OilAlpha's SpyNote/SpyMax RATs exfiltrate collected device data — SMS, contacts, media, captured audio/video and harvested credentials — back to operators over the same RAT C2 channel to dynamic-DNS servers. Observed C2: `ho1hm2.ddns.net` on TCP 44414 (Cash Incentives sample) and `ho1hm2.ddns.net` / `ho2hm1.ddns.net` on TCP 44449 (NRC Business sample), resolving to IPs such as 206.189.98.34 and 141.255.145.221.
- **Why a hunt, not a rule:** Exfiltration is bundled inside the opaque, often-encrypted mobile RAT stream and is largely off-network when the handset uses cellular data, so coverage is partial and byte counts vary per victim — a fixed threshold misses low-and-slow theft and false-alarms on legitimate large uploads. The durable hunt is correlating the *destination class + port rarity + directional byte asymmetry + beacon regularity* on the same device where on-network visibility exists, which needs per-device baselining and analyst judgement rather than a static alert. (If a specific live DDNS host + port pair is confirmed active, that discrete tuple is precise enough to hand to detection-engineering.)
- **Cross-reference:** the discrete DDNS C2 domains, ports 44414/44449, and `kssnew.online` credential portal are already routed to the detection lane (T1568/T1571/T1071/T1056.003); this hunt covers the *behavioral exfil pattern* those rules can't fully capture.

## Data sources required

- Firewall / NetFlow / proxy egress logs from corporate WiFi and mobile-VPN segments (src device, dest IP/host, dest port, bytes in/out, session duration)
- DNS resolver logs (device -> DDNS FQDN resolution feeding the flow)
- MTD / MDM network-event telemetry where the agent reports per-app connections
- NIDS / PCAP for beacon-cadence and directionality analysis, where available

## Query starting point

Platform: `Splunk SPL`

```
index=firewall OR index=netflow (src_zone=wifi OR src_zone=mobile_vpn OR src_category=mobile)
| eval dhost=lower(coalesce(dest_host,resolved_domain,dest_dns))
| eval nonstd_port=if(dest_port>=40000 AND dest_port<=49999,1,0)
| eval known_c2=if(match(dhost,"(ddns\.net|sytes\.net|dynns\.com|serveftp\.com)$")
                   OR cidrmatch("206.189.98.34/32",dest_ip)
                   OR cidrmatch("141.255.145.221/32",dest_ip)
                   OR cidrmatch("141.255.144.8/32",dest_ip)
                   OR cidrmatch("176.123.21.4/32",dest_ip)
                   OR cidrmatch("145.14.156.148/32",dest_ip)
                   OR cidrmatch("134.122.75.238/32",dest_ip),1,0)
| eval hot_port=if(dest_port=44414 OR dest_port=44449,1,0)
| stats sum(bytes_out) as up sum(bytes_in) as down count as sessions
        dc(_time) as beacon_intervals values(dest_port) as ports
        values(dhost) as hosts by src_ip, dest_ip
| eval up_ratio=round(up/(down+1),2)
| where (hot_port=1) OR (known_c2=1) OR (up_ratio>3 AND up>5000000 AND sessions>10)
| sort - up_ratio, - up
```

## Triage guidance

- **Likely malicious:** A mobile device holding sustained outbound sessions to a DDNS host or OilAlpha IP on port 44414/44449; strong upload-to-download asymmetry with regular beacon intervals; the same device also flagged in HUNT-01/HUNT-03. Any traffic to `kssnew.online` from a handset after app install (credential exfil) is high-signal.
- **Likely benign / expected:** Legitimate cloud-backup/photo-sync uploads to well-known CDNs/providers (not DDNS, standard 443); video-call apps with high bidirectional volume; enterprise MDM check-ins. High upload alone to a reputable destination on 443 is not this pattern — require the DDNS/high-port destination class.
- **Pivot next:** Confirm the destination against intel infrastructure and the source device against MDM inventory; if the device runs a spoofed OilAlpha app talking to DDNS C2, treat it as a confirmed active compromise and escalate to incident-response immediately (rotate any org credentials the device could reach). Feed the confirmed live host:port tuple to detection-engineering. Run HUNT-02 to enumerate sibling infrastructure.

## References

- https://assets.recordedfuture.com/insikt-report-pdfs/2024/cta-2024-0709.pdf
- https://www.recordedfuture.com/research/oilalpha-likely-pro-houthi-group-targeting-arabian-peninsula
- https://attack.mitre.org/techniques/T1041/
