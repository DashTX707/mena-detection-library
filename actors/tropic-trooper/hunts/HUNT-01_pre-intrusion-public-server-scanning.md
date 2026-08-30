# Hunt: Tropic Trooper — pre-intrusion scanning of the public-facing attack surface

- **Hypothesis:** If Tropic Trooper is preparing to intrude, then before any web shell lands we should see *perimeter reconnaissance*: bursts of vulnerability probing against our internet-facing Umbraco/.NET CMS, Microsoft Exchange and Adobe ColdFusion servers — path-fuzzing for CMS admin/module endpoints, ProxyShell autodiscover/PowerShell-endpoint probes (CVE-2021-34473/34523/31207) and ColdFusion CVE-2023-26360 probes — from a small set of source IPs/ASNs that then either go quiet or convert to a successful exploit POST. The tell is not any single 404 but a *scan-then-silence-then-write* shape on the same asset: many anomalous requests to rarely-hit endpoints, followed by a first-ever `App_Web_*.dll` write into the ASP.NET temporary-files tree. Either half is thin; the pair on one server is the finding.
- **ATT&CK:**
  - T1595.002 — Active Scanning: Vulnerability Scanning (reconnaissance) — off-victim/perimeter probing of internet-facing CMS/Exchange/ColdFusion for exploitable versions before the China Chopper web shell is planted; this hunt keys on the pre-exploit scan burst and its convergence to a foothold.

- **Actor procedure:** Kaspersky's 2024 report on the Middle East government intrusion assesses initial access came through exploitation of a public-facing open-source Umbraco (.NET) CMS. Related/earlier Tropic Trooper (Earth Centaur) intrusions exploited internet-facing Microsoft Exchange (ProxyLogon/ProxyShell) and IIS, and the pack lists Adobe ColdFusion CVE-2023-26360 among the actor's public-app vectors. Public-facing server scanning to find an exploitable, unpatched instance precedes deployment of the China Chopper web shell (compiled as an `App_Web_{8-char}.dll` Umbraco module). The scanning itself is generic — internet-wide opportunistic probing looks the same — which is exactly why it is a hunt, judged by convergence onto a real, exploitable asset rather than by the probe alone.
- **Why a hunt, not a rule:** Internet-facing servers are scanned constantly by everyone (Shodan, Censys, commodity botnets, researchers); a standalone "vuln scan detected" alert on perimeter logs is pure noise and un-attributable to this actor. Value comes from *correlation and judgement*: filtering the background scan hum down to probes that (a) target the specific technologies Tropic Trooper exploits, on (b) assets that are actually running a vulnerable version, and (c) time-precede a first-seen web-shell artifact or anomalous authenticated POST on that same host. That triage is analyst work over aggregated context, not a threshold an alert can safely fire on. If a durable relational observable falls out — e.g., "a source IP that probed our ColdFusion CVE-2023-26360 endpoint is the same IP that later authenticated a module upload" — hand that scoped analytic to detection-engineering; do not alert on scanning volume alone.

## Data sources required

- Web-server / reverse-proxy / WAF access logs for all internet-facing IIS + Umbraco/.NET, Exchange (OWA/ECP/autodiscover, `/powershell`) and ColdFusion (`/CFIDE/adminapi/`, `/cf_scripts/`) hosts — URI, method, status, user-agent, source IP
- External attack-surface / asset inventory: which perimeter hosts run Umbraco, Exchange, ColdFusion, and at what patch level (to score "actually vulnerable")
- Threat-intel enrichment on source IP/ASN (hosting/VPS reputation, prior scan history)
- File-integrity / EDR file-create telemetry on the web root and ASP.NET Temporary Files tree (the convergence signal from HUNT-02/detection pack T1190/T1505.003)

## Query starting point

Platform: `Splunk SPL` — surface source IPs that probe Tropic-Trooper-relevant endpoints in a burst against a vulnerable asset, then pivot to any subsequent write

```spl
index=web sourcetype=iis OR sourcetype=nginx OR sourcetype=waf
  earliest=-30d
| eval tech=case(
    like(lower(uri_path),"%/umbraco/%") OR like(lower(uri_path),"%app_web_%"), "umbraco",
    like(lower(uri_path),"%/autodiscover/%") OR like(lower(uri_path),"%/powershell%") OR like(lower(uri_path),"%/ecp/%"), "exchange",
    like(lower(uri_path),"%/cfide/%") OR like(lower(uri_path),"%/cf_scripts/%") OR like(lower(uri_path),"%adminapi%"), "coldfusion",
    true(), "other")
| where tech!="other"
| stats count AS hits, dc(uri_path) AS distinct_paths, values(tech) AS tech,
        sum(eval(status>=500)) AS server_errors,
        earliest(_time) AS first_seen, latest(_time) AS last_seen,
        values(http_user_agent) AS agents
    by src_ip, host
| where distinct_paths >= 15 AND hits >= 50          /* fuzzing shape, not a normal user */
| eval scan_window_min=round((last_seen-first_seen)/60,1)
| lookup asset_inventory host OUTPUT vulnerable_service is_perimeter
| where is_perimeter="true"                          /* only internet-facing */
| sort - distinct_paths
/* PIVOT: for surviving src_ip/host pairs, check FileCreate on that host's
   web root / ASP.NET temp tree AFTER last_seen -> scan-then-write = strong finding */
```

## Triage guidance

- **Likely malicious:** a tight probe burst against Umbraco module/admin or ProxyShell/ColdFusion endpoints on a host that is *actually* running the vulnerable version, from a VPS/hosting-ASN IP with no business reason to reach it, that time-precedes a first-ever `App_Web_*.dll` write or an anomalous authenticated module upload on the same host; the same source IP reappearing across recon and the exploit write.
- **Likely benign / expected:** internet-wide scanners (Shodan, Censys, BinaryEdge, security-researcher ASNs — baseline and tag them), your own external vuln scanner (Qualys/Tenable/Nessus from a known scan-source IP on a schedule), uptime/monitoring probes, and search-engine crawlers. High endpoint diversity from a *known* scanner is expected; the same shape from an unknown hosting IP against a genuinely-vulnerable asset is not.
- **Pivot next:** if scan-then-write converges on one host, treat as an active exploitation of a public-facing app — pivot immediately to the web-shell hunt (detection pack T1190/T1505.003: `App_Web_*.dll` modules, `w3wp.exe` spawning `cmd.exe`), preserve the pre-exploit access logs as attribution intel, block the source IP/ASN, and if a web shell is confirmed escalate to incident-response-coordinator. Feed the source IP/ASN to HUNT-02 infrastructure tracking.

## References

- https://securelist.com/new-tropic-trooper-web-shell-infection/113737/
- https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html
- https://attack.mitre.org/groups/G0081/
- https://attack.mitre.org/techniques/T1595/002/
