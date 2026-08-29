# Hunt: WIRTE web C2 & ingress — rare hardcoded User-Agents, HTML-tag-embedded payloads, Cloudflare-fronted beacons and second-stage pulls

- **Hypothesis:** If a WIRTE implant (LitePower / IronWind / Havoc) is beaconing, then despite Cloudflare fronting hiding the true C2 IP we should surface the channel from web-proxy telemetry: HTTP(S) GET/POST from a script-host or sideloaded process carrying a rare hardcoded User-Agent (the LitePower `Mozilla/5.0 ... rv:FTS_xx ... Firefox/2.0` family whose `rv` is varied per intrusion, or IronWind's expected-only UA), a consistent beacon+sleep cadence (~60–100 s randomized), responses whose bodies carry the next stage *embedded between HTML tags*, and file-write-then-execute of a pulled payload — to Cloudflare-fronted health/finance/country-themed domains or `requestinspector.com`/`master-dental.com`.
- **ATT&CK:**
  - T1071.001 — Application Layer Protocol: Web Protocols (command-and-control) — LitePower HTTP GET/POST with hardcoded rare UA; IronWind/Havoc HTML-tag-embedded payloads served only to the expected UA
  - T1105 — Ingress Tool Transfer (command-and-control) — second-stage/Havoc Demon pulls; payloads embedded in HTML then written and executed
- **Actor procedure:** LitePower sends command results via HTTP POST and fetches PowerShell commands via HTTP GET using a unique hardcoded User-Agent (`Mozilla/5.0 ... rv:FTS_06 ... Firefox/2.0`) whose `rv` field is varied per intrusion for tracking, on a ~60–100 s randomized sleep loop. IronWind/Havoc beacon over HTTP and retrieve next-stage payloads embedded within HTML tags, returning them only to a request bearing the expected user agent (otherwise redirecting to a legitimate site). C2 is Cloudflare-fronted (hiding the real VPS), to themed domains such as `master-dental.com` and the `requestinspector.com` profiling endpoint. Older intrusions used non-standard TLS ports (2083/2087/8443, T1571 — detection lane) with per-port cert CNs.
- **Why a hunt, not a rule:** Cloudflare fronting collapses the destination IP into a shared, benign-looking range, and a single beacon is indistinguishable from ordinary web traffic — so an IP/domain rule expires fast (Level 1) and a UA rule mis-fires on legacy clients. The durable, harder-to-change signal (Summiting Level 3–4, header/behavioral) is the *combination*: an anomalous/rare User-Agent (obsolete `Firefox/2.0`, malformed `rv` token) issued by a *script-host or sideloaded process rather than a browser*, on a regular sleep cadence, receiving HTML-wrapped binary content, followed by a local file-write+exec. Separating that from real browsers and legit API clients needs per-environment UA/beaconing baselining — analyst work.

## Data sources required

- Proxy / web-gateway logs (User-Agent, method, URI, response content-type/size, referer, bytes in/out, timing) and TLS metadata (SNI, JA3, cert CN)
- Sysmon EID 1/3 — the process making the connection (`powershell.exe`, sideload host) and its lineage
- Sysmon EID 11 — file-write of a pulled payload right after a C2 GET (ingress → drop → exec)
- NDR / Zeek for beacon-interval (sleep-loop) analytics and Havoc-default signatures

## Query starting point

Platform: `Splunk SPL`

```
index=proxy
| eval ua=lower(http_user_agent), proc=lower(process_name)
| eval rare_ua=if(match(ua,"firefox/2\.0") OR match(ua,"rv:fts_") 
                  OR match(ua,"rv:[a-z]") /* malformed rv token */,1,0)
| eval nonbrowser=if(match(proc,"(powershell|wscript|cscript|rundll32|regsvr32)\.exe$") 
                     OR match(proc,"(?i)(setup_wm|pinenrollmentbroker|propsys|version)"),1,0)
| eval themed_dst=if(match(lower(dest_host),"(dental|pharmacy|health|bank|requestinspector|master-dental)"),1,0)
| where rare_ua=1 OR (nonbrowser=1 AND method IN ("GET","POST")) OR themed_dst=1
| bin _time span=5m
| stats count avg(bytes_out) as avg_out dc(uri_path) as paths values(ua) as uas 
        values(dest_host) as dests by _time, src_ip, proc
| where count>=3   /* repeated beacons in window */
| sort - count
```

Pivot beaconing src/process into Sysmon EID 11 for a payload written to disk right after a GET (ingress), and compute inter-arrival times per src→dst to expose the ~60–100 s sleep cadence; check response `content-type=text/html` bodies carrying embedded binary (HTML-tag payloads).

## Triage guidance

- **Likely malicious:** an obsolete/rare/malformed User-Agent (`Firefox/2.0`, `rv:FTS_xx`) from `powershell.exe`/a sideloaded binary rather than a browser; regular ~60–100 s beacons to a Cloudflare-fronted themed domain; HTML responses carrying embedded binary followed by a local EXE/DLL write+exec; a POST to `requestinspector.com`.
- **Likely benign / expected:** real browsers with current UAs; legit API clients/updaters with stable UAs to known SaaS; monitoring agents polling on an interval (baseline these src+dst+UA). The discriminators are *non-browser process + anomalous UA + HTML-wrapped payload*.
- **Pivot next:** tie the beaconing process back to the loader/persistence (HUNT-03/04/05) and the recon burst (HUNT-07); if a payload was pulled and executed, pivot to collection/exfil (HUNT-09) and, if the fetch keyed a decode off oref.org.il, to the wiper early-warning (HUNT-06). Confirmed implant C2 on a live host is an incident — escalate to incident-response-coordinator; the true C2 domains/IPs (post-Cloudflare) go to detection-engineering as blocks (IOC pivots, not the hunt basis).

## References

- https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/
- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://attack.mitre.org/groups/G0090/
