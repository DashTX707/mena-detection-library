# Hunt: APT39 web-service bidirectional C2 (legitimate-SaaS blending)

- **Hypothesis:** If APT39 is using a legitimate web service for bidirectional C2 (posting output and pulling tasking through a sanctioned SaaS/CDN endpoint so the traffic looks like normal web usage), then we should see an endpoint communicating with a well-known web service in a *machine-like, automation* pattern that a human user wouldn't produce — highly regular polling intervals, requests originating from a non-browser process, near-symmetric small request/response pairs, and activity outside the user's working hours — to a service the *host* has no legitimate reason to use even if the *org* does.
- **ATT&CK:**
  - T1102.002 — Web Service: Bidirectional Communication (command-and-control)

- **Actor procedure:** APT39 blends C2 into sanctioned web traffic, using legitimate web services and web-facing infrastructure for two-way communication so beacons hide inside the noise of normal HTTPS to popular domains. The implant fetches commands and returns collected surveillance data through the same service, avoiding a bespoke C2 domain that would stand out on DNS/proxy review.
- **Why a hunt, not a rule:** Traffic to legitimate web services is, by definition, everywhere and expected — a rule on "connections to \<popular SaaS\>" is unusable. The discriminating features are *behavioral*: which local *process* is talking (non-browser), the *regularity* (low-jitter beaconing), the *timing* (off-hours automation), and the *host-vs-service mismatch* (this endpoint has no reason to automate against this service). Establishing per-service, per-process baselines and spotting automation anomalies is judgement-heavy → hunt. A durable finding — e.g., a specific non-browser process beaconing to a service on a fixed interval (Summiting Level 3–4, behavior-core) — can be handed to detection-engineering.

## Data sources required

- Proxy / TLS-inspection / Zeek `http.log` + `ssl.log` (SNI, JA3/JA3S, request cadence, bytes-in/out)
- Sysmon EID 3 (network connect) + EID 1 — the *process* initiating the web-service connections (non-browser is the tell)
- DNS logs (resolution of the service FQDN by non-browser processes)
- User work-hours / process baseline (which processes legitimately talk to which SaaS)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — non-browser process beaconing to a web service with low jitter / off-hours automation

```kusto
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","safari.exe","brave.exe"]);
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where RemoteUrl has_any ("api.","cdn.","raw.","pastebin","github","gitlab","dropbox","onedrive","blob.core","s3.amazonaws","telegram","discord")
| where InitiatingProcessFileName !in~ (browsers)          // web-service talk from a non-browser = suspect
| extend hour = datetime_part("hour", TimeGenerated)
| summarize conns = count(),
            intervals = make_list(TimeGenerated, 200),
            bytesOut = sum(tolong(SentBytes)), bytesIn = sum(tolong(ReceivedBytes)),
            offHours = countif(hour < 7 or hour > 19),
            hosts = dcount(DeviceName)
        by InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| extend offHoursRatio = todouble(offHours) / conns
| where conns >= 30 and offHoursRatio > 0.4                 // sustained + heavily off-hours
| order by conns desc
// Post-filter: compute inter-arrival stddev on `intervals`; low jitter = automated beacon.
// Exclude signed updaters/telemetry agents by process signer+path (wiki baseline).
```

## Triage guidance

- **Likely malicious:** a non-browser, unsigned/oddly-located process making sustained, low-jitter (near-fixed-interval) requests to a public web service (paste/code-hosting/cloud-storage/messaging APIs), heavily weighted to off-hours, with near-symmetric small payloads and no corresponding user activity — especially on a host also flagged in HUNT-01. This is classic dead-drop/bidirectional web-service C2.
- **Likely benign / expected:** OS/app updaters, telemetry/crash reporters, backup and sync clients (OneDrive/Dropbox), package managers, and monitoring agents legitimately automate against web services on regular intervals — allowlist by signer + install path + expected destination. A signed sync client talking to OneDrive is expected; an unknown binary in `%TEMP%` polling a paste API every 60s is not.
- **Pivot next:** capture the request/response bodies (if TLS-inspected) to confirm tasking/exfil semantics; correlate the process with the collection suite (HUNT-01) and exfil-volume anomalies (HUNT-04); pivot the exact service account/URL path to look for other victims. Confirmed two-way tasking over a web service is active C2 → escalate to IR.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1102/002/
- https://www.mandiant.com/resources/blog/apt39-iranian-cyber-espionage-group-focused-on-personal-information
