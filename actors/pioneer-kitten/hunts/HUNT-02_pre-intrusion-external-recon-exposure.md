# Hunt: Pioneer Kitten pre-intrusion external reconnaissance and edge exposure

- **Hypothesis:** If Pioneer Kitten is targeting our internet-facing estate, then before any exploit lands they will have *fingerprinted* our exposed edge appliances through third-party technical databases (Shodan) — meaning the earliest observable is not on our endpoints at all but in our **external attack surface**: an internet-facing NetScaler / Ivanti / PAN-OS GlobalProtect / F5 / Check Point device that (a) is discoverable in Shodan/Censys with a version banner matching one of the actor's target CVEs, and (b) shows a burst of low-and-slow probing/banner-grabbing from scanner/census infrastructure shortly before any exploit attempt. The hunt is an outside-in exposure sweep, not an endpoint sweep.
- **ATT&CK:**
  - T1596 — Search Open Technical Databases (reconnaissance) — actors use Shodan.io to enumerate internet infrastructure hosting devices vulnerable to specific edge/VPN CVEs

- **Actor procedure:** Pioneer Kitten uses the Shodan search engine to identify and enumerate internet-facing devices exposing the specific product/versions vulnerable to their preferred CVEs — Citrix NetScaler (CVE-2019-19781, CVE-2023-3519), F5 BIG-IP (CVE-2022-1388), Pulse/Ivanti Connect Secure (CVE-2024-21887), PAN-OS GlobalProtect (CVE-2024-3400), Check Point Security Gateway (CVE-2024-24919). Shodan queries select victims by exposed banner/version, so any of our appliances that answers Shodan with a vulnerable fingerprint is a pre-selected target.
- **Why a hunt, not a rule:** The Shodan query itself happens on a third party's infrastructure and is completely off-victim — there is no log of "the adversary searched Shodan for us," so nothing can alert. The defensible action is the inverse: proactively enumerate what *we* expose that matches the actor's target profile, and correlate that exposure with perimeter probe bursts — a periodic, judgement-driven exposure hunt rather than a real-time alert. Perimeter scanning is constant internet background noise, so a probe-count rule alone is pure noise; value comes from intersecting a *vulnerable-versioned* exposed asset with probing from census/scanner ranges. Where an appliance is found exposed with a vulnerable banner, that is a patch/mitigation action for vulnerability management, not an alert.

## Data sources required

- External attack-surface / exposure feeds: Shodan, Censys, our own ASM tooling — banners, product/version, TLS certs for our public IP ranges
- Appliance/version inventory + patch state for all internet-facing NetScaler / Ivanti / PAN-OS / F5 / Check Point devices
- Perimeter firewall / IDS / WAF / edge-appliance access logs (inbound probe and banner-grab volume by source)
- Advisory infrastructure watchlist (AA24-241A Table 10/11 IPs and domains) for source correlation

## Query starting point

Platform: `SPL / Splunk` — exposed vulnerable-versioned edge assets intersected with pre-exploit probe bursts

```spl
(* NetScaler/Ivanti/PAN-OS/F5/Check Point edge banner monitoring *)
index=asm_exposure sourcetype=shodan OR sourcetype=censys
    (product="Citrix*" OR product="NetScaler*" OR product="Ivanti*" OR product="Pulse*"
     OR product="PAN-OS*" OR product="GlobalProtect*" OR product="BIG-IP*" OR product="Check Point*")
| eval vuln_ver=case(
      like(version,"%12.1%") OR like(version,"%13.0%"), "netscaler_cve-2023-3519_candidate",
      like(product,"%GlobalProtect%"), "panos_cve-2024-3400_candidate",
      like(product,"%Check Point%"), "checkpoint_cve-2024-24919_candidate",
      1==1, "review")
| join type=left dest_ip
    [ search index=perimeter (action=probe OR action=denied OR http_status=404)
      earliest=-14d
    | stats count as probe_count dc(src_ip) as distinct_scanners values(src_ip) as scanners by dest_ip ]
| where probe_count > 50 OR isnotnull(vuln_ver)
| table dest_ip product version vuln_ver probe_count distinct_scanners scanners
| sort - probe_count
```

## Triage guidance

- **Likely malicious / actionable:** an internet-facing edge appliance answering Shodan/Censys with a version banner in the vulnerable range for an actor CVE — this is a pre-selected target regardless of who queried it; a probe/banner-grab burst against that asset from an advisory IP (AA24-241A Table 10/11) or from hosting/VPS ranges immediately preceding a spike of requests to the vulnerable endpoint path (`/xui/common/images/`, GlobalProtect, Check Point CVE-2024-24919 path).
- **Likely benign / expected:** continuous, undirected internet-wide scanning hits every exposed IP — background radiation, not targeting; legitimate uptime/security scanners (our own ASM vendor, Qualys/Tenable external, search-engine census) probe on a known cadence — allowlist their ranges; a fully patched appliance with a current banner is exposed-but-not-vulnerable.
- **Pivot next:** any exposed vulnerable-versioned appliance is an immediate patch/virtual-patch action for vulnerability management (not an alert) and a trigger to pull that appliance's own logs for post-exploit artifacts (webshells `netscaler.php`/`ui_style.php`/`sanpdebug.php`, `/xui/common/images/`, `netscaler.1` — detection pack T1505.003/T1133). A vulnerable exposure plus a directed probe burst from advisory infrastructure warrants pre-emptive threat-hunting of that appliance's host and continued monitoring.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a
- https://attack.mitre.org/groups/G0117/
- https://attack.mitre.org/techniques/T1596/
