# Hunt: Cotton Sandstorm exfiltration over web service & hack-and-leak staging

- **Hypothesis:** If ASA is executing its signature hack-and-leak model against us, then before stolen data surfaces publicly on a leak site, we should observe the exfil hop — anomalously large or unusually-timed outbound transfers from sensitive data stores to newly-seen web-service destinations (actor-controlled leak/staging servers or abused SaaS/file-sharing), and, for camera/streaming victims, sustained outbound RTSP/media pulls to harvesting servers. The hunt keys on a volume/relationship anomaly (a data-holding host talking to a never-before-seen web destination in bulk), because the leak itself often surfaces externally first.
- **ATT&CK:**
  - T1567 — Exfiltration Over Web Service (exfiltration)

- **Actor procedure:** Central to ASA's model: after stealing data it exfiltrates and publishes it — and makes harvested IP-camera content available to "clients" — via actor-controlled web services and servers (e.g. IP-camera content platforms at `5.230.56[.]148`, `77.91.74[.]158`, later `195.26.87[.]80`, `213.109.147[.]97`, `185.110.188[.]112`), leaking material to inflict reputational/psychological damage (T1567). Exfiltration to web services blends with normal outbound web traffic, so the leak frequently becomes visible externally (on a persona leak site) before it is caught on the wire.
- **Why a hunt, not a rule:** Exfil to a common web service is deliberately camouflaged in the vast volume of normal outbound HTTPS, and the destinations rotate (the advisory lists several staging IPs over time), so a destination-IOC rule ages out fast and a volume rule alone drowns in false positives from backups, cloud sync and SaaS. The discriminating signal is *relational and stacked*: a host that holds sensitive data suddenly moving bulk bytes to a destination it has never contacted, off-hours, to infrastructure that clusters with HUNT-03 pivots — a per-entity volume/never-before-seen/timing anomaly stack that needs baselining and judgement, not a threshold. Where a destination is confirmed actor infrastructure it becomes an IOC for the detection pack; the *discovery* is a hunt.

## Data sources required

- Web-proxy / firewall / NetFlow egress logs with bytes-out per destination and per host
- DLP / CASB (sensitive-data movement, cloud-file-share uploads, anomalous SaaS destinations)
- Per-host / per-user egress baseline (normal destinations and volumes, working hours)
- Data-store inventory (which hosts hold sensitive/regulated data — the crown jewels to watch)
- Threat-intel staging-infrastructure feeds (ASA leak/camera-harvest IPs and HUNT-03 domain pivots)

## Query starting point

Platform: `Splunk SPL` — bulk egress from a sensitive host to a never-before-seen web destination, off-hours

```
index=proxy OR index=netflow
| lookup sensitive_hosts.csv src_host OUTPUT data_class      ` restrict to crown-jewel data stores `
| where isnotnull(data_class)
| eval hour=strftime(_time,"%H")
` per-host 30d baseline of destinations this host has contacted before `
| join type=left src_host dest [ search index=proxy earliest=-30d@d latest=-1d@d
                                  | stats count AS seen_before by src_host dest ]
| eval seen_before=coalesce(seen_before,0)
| stats sum(bytes_out) AS bytes_out values(dest) AS dest max(seen_before) AS seen_before
        by src_host dest data_class hour
| where seen_before=0 AND bytes_out > 50000000        ` never-before-seen dest + >50MB out `
| eval offhours=if(hour<7 OR hour>19,1,0)
| lookup asa_staging_ioc.csv dest OUTPUT asa_infra     ` bonus: clusters with known ASA staging `
| sort - bytes_out
```

Companion (intel-side): monitor persona leak sites and Telegram channels (Cyber Court cluster — HUNT-02) for any dump referencing our org or data; for camera/streaming assets, watch for sustained outbound RTSP/media pulls to unfamiliar destinations.

## Triage guidance

- **Likely malicious:** a crown-jewel data store moving tens/hundreds of MB to a web destination it has never contacted, off-hours, especially if that destination clusters with HUNT-03 infrastructure pivots or the advisory's staging IPs; a sudden sustained RTSP/media egress from a camera/streaming asset to an unfamiliar host; exfil timing that shortly precedes a persona leak-site post.
- **Likely benign / expected:** scheduled backups and cloud sync (OneDrive/Google Drive/S3) to known corporate tenants; legitimate large SaaS uploads by known users; CDN/media distribution from streaming assets to known endpoints. Baseline and allowlist sanctioned backup/cloud destinations and normal media-distribution targets; a known destination on a known cadence is expected.
- **Pivot next:** if bulk exfil to an unknown destination is confirmed, isolate the source host, block and preserve the destination, scope what data left, and pivot to the intrusion chain (HUNT-04/HUNT-06 WezRat, detection pack T1071.001 C2). Feed the destination back to HUNT-03 clustering and to the detection watchlist. Confirmed exfil of sensitive data is a live breach → escalate to IR immediately and prepare for a public leak (notify comms/legal, watch the persona leak sites).

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://blogs.microsoft.com/on-the-issues/2024/10/23/as-the-u-s-election-nears-russia-iran-and-china-step-up-influence-efforts/
- https://attack.mitre.org/techniques/T1567/
