# Hunt: Stealth Falcon — aax.me browser-side JS profiling, AV & software fingerprinting

- **Hypothesis:** If a target has visited a Stealth Falcon tracking link, then before any redirect the actor's `aax.me` page runs profiling JavaScript in the target's browser that betrays itself through a recognisable client-side pattern: a burst of `XMLHttpRequest`/`fetch` calls to **localhost/127.0.0.1 on antivirus-specific ports** (AV port-timing probes), ActiveX/Flash/Java/Office plugin enumeration, and timezone/user-agent/Tor-status collection — all against off-victim infrastructure. The hunt looks for that fingerprinting burst wherever we *can* see client-side execution (managed-browser DevTools/CSP telemetry, browser-isolation/RBI logs, or a controlled detonation of a captured link), because standard endpoint EDR will not see JS running inside the renderer.
- **ATT&CK:**
  - T1059.007 — Command and Scripting Interpreter: JavaScript (execution) — the profiling logic executes as browser-side JavaScript on the aax.me page.
  - T1518.001 — Software Discovery: Security Software Discovery (discovery) — AV fingerprinting via timed XHR probes to product-specific localhost ports (e.g. 12993 Avast, 44080 Avira, 1110 Kaspersky, 6646 McAfee, 6999 Trend Micro, 30606 ESET).
  - T1518 — Software Discovery (discovery) — enumeration of installed plugins/software (ActiveX, Flash, Java, MS Office) to select payload and lure.

- **Actor procedure:** The `aax.me` shortener served a profiling page that fingerprinted each visitor before redirecting: it probed localhost AV ports via XMLHttpRequest response-timing to infer which antivirus was installed, detected ActiveX/Flash/Java/Office availability, and collected timezone, plugins, user-agent and Tor-browser signals (including deanonymization attempts). The profile let operators tailor the follow-on lure/payload and avoid burning capability against well-defended or analyst/sandbox visitors. This is capability *aimed at* the victim but *executing on* attacker-controlled pages — the classic off-victim/browser-side recon problem.
- **Why a hunt, not a rule:** The code runs inside the browser renderer against a third-party page, which is a deliberate visibility gap — enterprise EDR, process-creation and AMSI telemetry never see it, so there is nothing to write a host rule against. Any signal we do get is indirect: localhost-port XHR bursts captured by a managed-browser extension, CSP `report-uri` violations, or the behaviour observed when a captured link is detonated in a browser-isolation lab. Deciding that a particular JS payload *is* the aax.me profiler — versus benign analytics/fraud-detection JS that also fingerprints browsers — requires reversing the script and matching the AV-port list; that is analysis, not alerting. Document the visibility gap itself as a finding: "we cannot see browser-side profiling on unmanaged/personal devices, which is exactly where these targets are hit."

## Data sources required

- Browser-isolation / remote-browser (RBI) execution logs, or a controlled detonation environment (instrumented headless browser) for captured aax.me links — the primary place JS behaviour is observable.
- Managed-browser telemetry: enterprise extension / CSP `report-uri` reports capturing outbound `XMLHttpRequest`/`fetch` to `localhost`/`127.0.0.1` on non-standard ports.
- Web-proxy logs (from HUNT-01) to identify which users reached an aax.me page in the first place — this hunt is the second stage of that pivot.
- Threat-intel: the documented AV-port list and profiling-script indicators from the Citizen Lab report.

## Query starting point

Platform: `Splunk SPL` (over browser-isolation / CSP-report / detonation-lab logs normalised into a `web` index)

```spl
index=browser_isolation OR index=csp_reports OR index=detonation
  sourcetype IN ("rbi:xhr","csp:violation","detonation:network")
| eval dest_host=coalesce(blocked_uri, dest_url, remote_url)
| rex field=dest_host "(?<probe_host>localhost|127\.0\.0\.1):(?<probe_port>\d+)"
| eval av_probe=case(
    probe_port=="12993","Avast", probe_port=="44080","Avira",
    probe_port=="1110","Kaspersky", probe_port=="6646","McAfee",
    probe_port=="6999","TrendMicro", probe_port=="30606","ESET")
| eval is_av_probe=if(isnotnull(av_probe),1,0)
| stats sum(is_av_probe) as av_port_probes dc(probe_port) as distinct_ports
        values(av_probe) as av_products values(referrer) as referrers
        min(_time) as first last(_time) as last
        by session_id user
| where av_port_probes >= 2 OR distinct_ports >= 3
| eval theme="aax.me-style client-side profiling"
| sort - av_port_probes
```

## Triage guidance

- **Likely malicious:** a single page session firing timed XHR/fetch probes to multiple AV-specific localhost ports back-to-back, combined with plugin/timezone/Tor enumeration and an inbound `Referer` of `aax.me` or a lookalike shortener; profiling that precedes a redirect to a `.docm` download or lookalike domain.
- **Likely benign / expected:** legitimate anti-fraud, bot-detection and DRM scripts (banking, ad-tech, streaming) also fingerprint browsers and occasionally probe localhost — baseline the sites that legitimately do this; a lone plugin-enumeration call without the AV-port burst is normal analytics. A managed device rarely hits these pages, so the *absence* of results on managed fleets is expected — it does not mean the technique is unused, it means it is being used against personal/unmanaged devices we cannot see.
- **Pivot next:** confirm by reversing the captured script and matching the AV-port set; pivot back to HUNT-01 to identify who received the link and forward to HUNT-03 to attribute the delivering persona. Where the gap is on personal devices, recommend RBI/managed-browser rollout and out-of-band warnings to at-risk users (a defensive-visibility finding, not an incident) — route the visibility gap to detection-engineering/IT, not an alert.

## References

- https://citizenlab.ca/2016/05/stealth-falcon/
- https://attack.mitre.org/techniques/T1059/007/
- https://attack.mitre.org/techniques/T1518/001/
- https://attack.mitre.org/techniques/T1518/
