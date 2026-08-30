# Hunt: Yellow Liderc strategic web compromise — browser fingerprinting JavaScript & profiling-domain exfil

- **Hypothesis:** If our users have transited a Tortoiseshell-compromised watering-hole site (primarily Israel-related maritime/shipping/logistics sites), then a browser process on a corporate host will, shortly after loading a legitimate third-party site, issue an outbound request carrying a host/software fingerprint to a *newly-registered or never-before-seen* attacker profiling/staging domain — with no user navigation to that domain. The evidence stacks an unexpected-relationship anomaly (browser child request to a domain the user never typed/clicked, sourced from injected JS) with a never-before-seen-destination anomaly (profiling domain absent from all prior proxy history) and, on selected targets, a follow-on drive-by payload fetch.
- **ATT&CK:**
  - T1608.004 — Stage Capabilities: Drive-by Target (resource-development)
  - T1592 — Gather Victim Host Information (reconnaissance)
  - T1592.002 — Gather Victim Host Information: Software (reconnaissance)
  - T1059.007 — Command and Scripting Interpreter: JavaScript (execution)
  - T1567 — Exfiltration Over Web Service (exfiltration)

- **Actor procedure:** Yellow Liderc / Imperial Kitten compromised legitimate websites and injected bespoke JavaScript that fingerprints each visitor — browser, OS, installed-software attributes — and exfiltrates the profile to attacker-controlled web services/domains. Operators review the fingerprints to distinguish intended targets from incidental traffic, then deliver a follow-on payload (leading to IMAPLoader) only to selected visitors. The reconnaissance, the JS execution, and the exfil all run client-side in the visitor's browser, so on the victim endpoint the only footprint is the browser's outbound requests.
- **Why a hunt, not a rule:** The malicious activity executes on a *third-party* site the victim legitimately visits, and the profiling request is an ordinary-looking HTTPS beacon to a domain that changes per campaign — an IOC-based rule expires the moment the domain rotates. The durable signal is behavioral and relational: a browser sub-request to a never-before-seen low-reputation domain that immediately follows navigation to a maritime/logistics site, carrying a fingerprint-shaped payload, with no direct user navigation. Deciding what is a profiling beacon versus normal ad-tech/analytics telemetry requires per-environment baselining and analyst judgement → hunt. The robust core (browser child request to a never-before-seen domain correlated to a target-sector referrer — Summiting Level 3–4) can seed a detection once the profiling-domain characteristics are pinned.

## Data sources required

- Web proxy / SWG logs with referrer, full URL, user-agent, bytes-out, domain age/reputation enrichment
- EDR/Sysmon EID 3 network + EID 1 process create — browser (`chrome/msedge/firefox.exe`) as InitiatingProcess and any child process spawned by the browser
- DNS resolver logs (newly-observed-domain / NXDOMAIN-then-resolve, low-TTL, newly-registered-domain feeds)
- Threat-intel enrichment: domain registration date, ASN, passive DNS

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — browser request to a never-before-seen domain right after a target-sector site, with fingerprint-sized upload

```kusto
let seen = DeviceNetworkEvents                              // 60d destination baseline
    | where TimeGenerated between (ago(60d)..ago(3d))
    | summarize by RemoteUrlDomain = tostring(parse_url(RemoteUrl).Host);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe"]);
DeviceNetworkEvents
| where TimeGenerated > ago(3d)
| where tolower(InitiatingProcessFileName) in (browsers)
| extend dom = tostring(parse_url(RemoteUrl).Host)
| where isnotempty(dom) and dom !in (seen)                  // never-before-seen destination
| where RemoteUrl !has "google" and RemoteUrl !has "microsoft"  // trim well-known telemetry
// keep small POST/GET beacons that look like a fingerprint blob rather than page loads
| where SentBytes between (200 .. 8000) and ReceivedBytes < 2000
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, dom, RemoteUrl, SentBytes
| order by TimeGenerated asc
// Pivot: enrich dom with registration age; correlate each hit to the prior browser navigation
// on the same host within 30s — was the referrer a maritime/shipping/logistics/Israel-related site?
```

Platform: `SPL / Splunk` — profiling-domain candidates by novelty + upload shape + sector referrer

```spl
index=proxy sourcetype=proxy
| eval dom=lower(url_domain), ref=lower(referrer_domain)
| search app_category!="analytics" app_category!="cdn"
| stats earliest(_time) as first count sum(bytes_out) as out values(ref) as referrers
        values(src) as hosts by dom
| where first > relative_time(now(),"-3d")            `# domain first-seen in last 3 days`
| where out>200 AND out<8000
| lookup newly_registered_domains domain as dom OUTPUT reg_age_days
| where reg_age_days<90
| sort - count
```

## Triage guidance

- **Likely malicious:** a browser issuing a small fixed-shape upload to a <90-day-old, low-reputation domain immediately after navigating to a maritime/shipping/logistics or Israel-related site; the destination appears in no prior proxy history and is not ad-tech/analytics; the same domain hit by multiple users who share that referrer; a follow-on fetch of an HTA/archive/installer from the same or linked infrastructure (pivot to `mshta` delivery in the detection pack).
- **Likely benign / expected:** legitimate analytics, ad-tech, tag-managers, RUM/telemetry, and CDN beacons also fire fingerprint-shaped requests from browsers — allowlist known ad/analytics domains and categories; a newly-seen but reputable SaaS/CDN domain adopted org-wide is expected. Fingerprint-shaped uploads to well-known trackers are noise, not this actor.
- **Pivot next:** pull the referring site's page content and hunt the injected `<script>` (web-content integrity / compare against a known-good baseline of that site); block the profiling domain and pivot passive DNS/ASN to sibling infrastructure and any staged payload; check whether any host that beaconed later shows `mshta`/side-load or IMAP C2 (HUNT-01) — that sequence means a visitor was selected and served. Confirmed payload delivery → escalate to IR.

## References

- https://www.pwc.com/gx/en/issues/cyber-security/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
- https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/
- https://attack.mitre.org/techniques/T1608/004/
- https://attack.mitre.org/techniques/T1592/
- https://attack.mitre.org/techniques/T1592/002/
- https://attack.mitre.org/techniques/T1059/007/
- https://attack.mitre.org/techniques/T1567/
