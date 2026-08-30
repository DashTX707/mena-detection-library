# Hunt: Stealth Falcon — aax.me tracking-link spear-phishing delivery & click

- **Hypothesis:** If Stealth Falcon is targeting our journalists/activists/dissident-affiliated users, then the earliest on-victim tell is not malware but a *link*: an inbound message (email, but critically also Twitter/DM/SMS the mail gateway never sees) carrying a URL routed through the actor's custom shortener/profiler, whose staged links follow the fixed pattern `aax.me/[0-9a-f]{5}` and whose bait predominantly concerns UAE political content. The hunt correlates the URL pattern seen at the web-proxy/DNS layer (the click) with the delivery channel and the recipient's risk profile — a single proxy hit to `aax.me` on a high-risk user, followed by a redirect to attacker bait, is the finding; either half alone is thin.
- **ATT&CK:**
  - T1608.005 — Stage Capabilities: Link Target (resource-development) — the actor stages per-target tracking links on the aax.me shortener; the `/[0-9a-f]{5}/` path is the hunt's core observable.
  - T1566.002 — Phishing: Spearphishing Link (initial-access) — the link is the primary delivery vector, sent via Twitter mentions and pretext emails after months of rapport-building.
  - T1204.001 — User Execution: Malicious Link (execution) — the compromise depends on the target *clicking*; the click is what surfaces in proxy/DNS telemetry.

- **Actor procedure:** Stealth Falcon delivered individually-crafted links to Emirati journalists, activists and dissidents through Twitter mentions and pretext emails from fictitious personas/orgs ("Andrew Dwight", "The Right to Fight"). The links passed through a bespoke URL-shortener/tracking service at `aax.me` (link regex `/aax.me/[0-9a-f]{5}/`). Citizen Lab enumerated 402+ aax.me links, ~73% referencing UAE political issues. On visit the shortener silently profiled the browser (see HUNT-02) before redirecting to bait content; a successful path led toward macro-document delivery (detect lane, T1566.001).
- **Why a hunt, not a rule:** Two reasons this is correlation/context work. First, most delivery is *off-victim* — a Twitter mention or a personal-webmail message never traverses the corporate mail gateway, so there is no delivery event to alert on; the only enterprise-visible moment is the click at the proxy. Second, `aax.me` is a real (historically legitimate-looking) shortener domain; a bare "any traffic to aax.me" alert lacks the context (recipient risk, redirect target, `[0-9a-f]{5}` path shape) that separates a targeting attempt from noise. The judgement — is this user a plausible Stealth Falcon target, does the redirect land on actor bait — is the hunt. If the `/aax.me/[0-9a-f]{5}/` path plus a confirmed malicious redirect proves consistently precise, hand the exact regex to detection-engineering as a scoped proxy analytic; do not ship "block all aax.me" as the deliverable.

## Data sources required

- Web-proxy / secure-web-gateway URL logs (full path, not just hostname) — to match `aax.me/[0-9a-f]{5}` and capture the redirect chain / `Referer`.
- DNS resolver logs — resolutions of `aax.me` and any co-hosted redirect targets when proxy path detail is unavailable.
- Mail-gateway URL-rewrite / click-tracking logs (e.g. Proofpoint URL Defense, Defender for Office 365 URL clicks) — for the email-delivered subset.
- HR/identity risk tagging of "high-risk / public-facing" users (journalists, activists, communications staff, exiled-diaspora contacts) — to weight recipients.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender for Endpoint + Defender for Office 365)`

```kusto
// Clicks/resolutions to the aax.me tracking pattern, weighted by user risk and redirect target
let riskUsers = _GetWatchlist('high_risk_public_facing_users') | project AccountUpn = SearchKey;
let aaxHits =
    union
    ( DeviceNetworkEvents
        | where TimeGenerated > ago(30d)
        | where RemoteUrl matches regex @"(?i)aax\.me/[0-9a-f]{5}"
             or RemoteUrl has "aax.me"
        | project TimeGenerated, DeviceName, InitiatingProcessAccountUpn, RemoteUrl, RemoteIP ),
    ( UrlClickEvents                                  // Defender for O365 Safe Links clicks
        | where TimeGenerated > ago(30d)
        | where Url has "aax.me"
        | project TimeGenerated, AccountUpn, Url, ActionType, Workload );
aaxHits
| extend patternMatch = RemoteUrl matches regex @"(?i)aax\.me/[0-9a-f]{5}" or Url matches regex @"(?i)aax\.me/[0-9a-f]{5}"
| extend isRiskUser = InitiatingProcessAccountUpn in (riskUsers) or AccountUpn in (riskUsers)
| order by isRiskUser desc, patternMatch desc, TimeGenerated asc
// Pivot: for each hit, pull the next proxy events on that device to reconstruct the redirect target
```

## Triage guidance

- **Likely malicious:** a `/aax.me/[0-9a-f]{5}/` path hit on a public-facing/high-risk user; the redirect chain landing on newly-registered lookalike infrastructure or a `.docm` download (cross-ref detect lane T1566.001/T1204.002); the link arriving after a period of social-media rapport from an unknown "journalist"/"NGO" contact; UAE-political bait themes in the landing page/subject.
- **Likely benign / expected:** organic shortener use — `aax.me` and similar services are also used for legitimate link-sharing; marketing/newsletter traffic; a hostname-only hit with no `[0-9a-f]{5}` path and a benign redirect. A single click by a low-risk user to a shortener that redirects to a mainstream site is expected noise.
- **Pivot next:** if the redirect leads to malware delivery, pivot to the endpoint (detect lane: WINWORD→wscript/powershell lineage, IEWebCache.vbs, IE Web Cache scheduled task) and treat as an active compromise — escalate to incident-response-coordinator. If it only profiles the browser, pivot to HUNT-02 (JS profiling / AV discovery) and to HUNT-03 (identify the delivering persona for takedown). Preserve the full URL and any per-target token as targeting intel.

## References

- https://citizenlab.ca/2016/05/stealth-falcon/
- https://attack.mitre.org/techniques/T1608/005/
- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1204/001/
