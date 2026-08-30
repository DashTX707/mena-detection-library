# Hunt: SideWinder — geofenced / server-side-polymorphic staging & time-based sandbox evasion

- **Hypothesis:** If SideWinder is staging a payload against an in-region victim of ours, then the delivery server will behave differently depending on *who* asks: a genuine in-region victim IP receives the weaponized HTA/JavaScript / .NET module, while a sandbox, a foreign IP, or a repeat request receives benign content or nothing. The observable tell is a *divergence* — the same staging URL that our corporate sandbox verdicted "clean/empty" actually served an executable payload when fetched from an in-region (e.g. Egypt/UAE/Saudi/Djibouti) egress IP, or served a different-hashed payload on each fetch (server-side polymorphism). A single benign sandbox verdict on a SideWinder-style URL is therefore *not* evidence of safety; the finding is the payload divergence across vantage points and the withheld-from-sandbox pattern.
- **ATT&CK:**
  - T1608.002 — Stage Capabilities: Upload Tool (resource-development) — SideWinder stages next-stage payloads (HTA/JS, .NET modules) on attacker-controlled servers and uses geofencing so only requests from targeted countries/victims receive the malicious payload, returning benign content otherwise.
  - T1497.003 — Virtualization/Sandbox Evasion: Time Based Evasion (stealth) — server-side polymorphism plus time/environment gating so payloads only detonate on genuine in-region victims and are withheld from automated analysis and repeat/out-of-scope requests.

- **Actor procedure:** BlackBerry documented SideWinder using server-side polymorphism against maritime targets — the delivery server mutates the payload per request so no two fetches yield the same hash, defeating hash-based detection and complicating sandbox correlation. Layered on top is geofencing/environmental gating: the staging server (often a look-alike domain from HUNT-01) serves the real mshta/HTA → obfuscated JavaScript → .NET ModuleInstaller chain only to requests that look like genuine in-region victims, and returns benign or empty content to sandboxes, scanners and out-of-region IPs. This is why the link/attachment lane (T1566.002) frequently yields "no verdict" in automated detonation.
- **Why a hunt, not a rule:** The staging and evasion logic lives on adversary infrastructure — it is not endpoint-observable, and by design it hides from the very sandbox that would produce an alert. A "clean" automated verdict is the *expected* adversary outcome, not proof of safety, so you cannot write a rule on the sandbox result. The durable work is a deliberate investigative act: re-fetch the suspect URL from a controlled in-region vantage point, compare payloads across vantage points and across repeat requests, and reason about the divergence — human-driven detonation and comparison, not automated alerting. If a stable server-side-polymorphism fingerprint emerges (e.g. consistent response-size banding, header quirk, JA3S), hand that to detection-engineering as a network analytic.

## Data sources required

- Email-gateway / URL-detonation verdict logs, especially URLs that returned "clean/empty/no content" (the withheld-from-sandbox signal)
- A controlled in-region retrieval capability (in-region VPS/sensor in the targeted geographies) to re-request suspect URLs from a plausible victim vantage point
- Web-proxy logs: response sizes/hashes for repeat requests to the same host/URI (per-request mutation = polymorphism)
- Passive DNS / hosting telemetry linking the staging host to the HUNT-01 look-alike domain cluster

## Query starting point

Platform: `Splunk SPL` — surface suspect staging URLs that were withheld from the sandbox, then flag hosts whose per-request response hashes/sizes diverge

```spl
(index=email sourcetype=proxy_url_detonation) OR (index=proxy sourcetype=web_proxy)
| eval url_domain=lower(url_domain)
``` join to the HUNT-01 look-alike watchlist / SideWinder domain cluster ```
| lookup sidewinder_lookalike_nrd Domain AS url_domain OUTPUT registrar nameserver
| search nameserver=* OR registrar=*
| eval withheld=if(sourcetype=="proxy_url_detonation" AND (verdict="clean" OR response_bytes<50 OR http_status IN(204,403,404)), 1, 0)
``` per-request payload mutation: many distinct response hashes/sizes for the SAME uri = server-side polymorphism ```
| stats dc(response_hash) AS distinct_payload_hashes
        dc(response_bytes) AS distinct_sizes
        values(verdict) AS verdicts
        sum(withheld) AS withheld_fetches
        count AS total_fetches
        values(src_ip) AS requesting_hosts
        by url_domain, uri_path
| where (distinct_payload_hashes>=3 AND total_fetches>=3) OR withheld_fetches>0
| sort - distinct_payload_hashes
``` NEXT (manual): re-fetch each url from an in-region sensor and compare payload to the sandbox "clean" verdict ```
```

## Triage guidance

- **Likely malicious:** a SideWinder-cluster URL that the corporate sandbox verdicted clean/empty but which serves an HTA/JavaScript or Base64 .NET payload when fetched from an in-region victim-like IP; the same URI returning a different response hash on every request (polymorphism); staging host that responds only to in-region source IPs / specific user-agents and 403/404s everything else; payload that runs mshta/`RunHTMLApplication` or manipulates `COMPLUS_Version` once detonated.
- **Likely benign / expected:** legitimate CDNs and A/B-testing endpoints also vary response bytes per request — cluster only on hosts already tied to the HUNT-01 look-alike domain set, not arbitrary varying hosts; geo-load-balanced legitimate sites; empty responses from decommissioned infrastructure. Per-request size variance *without* a brand-impersonation or lure linkage is not by itself SideWinder.
- **Pivot next:** if in-region re-fetch yields a live payload, preserve it for sample clustering (HUNT-04), extract the next-stage URL/domains and feed to HUNT-01, and sweep endpoints that received the original lure for the EQNEDT32→mshta→.NET loader chain. A confirmed payload delivered to any of our hosts is an active intrusion — escalate to incident-response-coordinator. Share the staging infrastructure + polymorphism fingerprint with cti-expert.

## References

- https://www.darkreading.com/cyberattacks-data-breaches/sidewinder-intensifies-attacks-maritime-sector
- https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/
- https://thehackernews.com/2025/03/sidewinder-apt-targets-maritime-nuclear.html
- https://attack.mitre.org/techniques/T1608/002/
- https://attack.mitre.org/techniques/T1497/003/
