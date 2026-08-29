# Hunt: WIRTE spearphishing-link delivery & click-through — lure PDFs with shortener redirects to IP-gated archive/credential pages

- **Hypothesis:** If WIRTE is using its link-based delivery arm against us, then we should observe a coherent lure→click→fetch chain: an inbound lure PDF (or email body) carrying a URL-shortener-style link (e.g. `theshortner[.]com`) or a Docdroid-lookalike page (`suppertools[.]com`, `healthscratches[.]com`), a user click recorded in proxy/URL-detonation telemetry to a newly-registered/redirecting destination, and — where the attacker's IP-gate lets us through — a subsequent RAR/archive download or a credential-harvest page, with the whole chain themed to Arabic geopolitical or Israeli-authority lures.
- **ATT&CK:**
  - T1566.002 — Phishing: Spearphishing Link (initial-access) — lure PDFs/emails with shortener + Docdroid-mimic phishing links
  - T1204.001 — User Execution: Malicious Link (execution) — the victim clicking the embedded link to fetch the archive / reach the phishing page
- **Actor procedure:** WIRTE embeds a URL-shortener-style link (`theshortner[.]com`) inside a lure PDF that redirects to a RAR archive (Beirut/Lebanon-war themed in Sep 2024), and hosts Docdroid-mimicking phishing pages (`suppertools[.]com`, `healthscratches[.]com`) that serve the malicious document or content conditionally on visitor IP (so a sandbox from the wrong geo sees only benign content). Requiring a click keeps sender-side attachment scanning quiet; the IP-gating frustrates automated detonation.
- **Why a hunt, not a rule:** click-through to a shortener or a new domain is enormously common and cannot be alerted wholesale, and the attacker's IP-gating means detonation sandboxes frequently see a clean redirect target — so a URL-reputation rule under-fires by design. The hunt value is correlating the *inbound artifact* (PDF carrying a shortener/lookalike link, themed lure) with the *click* and any *follow-on archive fetch* on the same user/host in a short window, and looking specifically at redirect chains that terminate in a fresh themed domain — analyst judgement over lure theme and redirect topology, not a threshold.

## Data sources required

- Mail-gateway logs with extracted URLs / link-rewrite + detonation verdicts, attachment (PDF) metadata
- Proxy / web-gateway logs (full URL, redirect chain / referer, response content-type) and DNS
- Endpoint browser history / EDR network telemetry to tie a click to a host and downstream download
- URL-shortener and newly-registered-domain / redirect-tracking enrichment

## Query starting point

Platform: `KQL / Sentinel`

```
// Inbound PDFs/emails carrying shortener or lookalike links, then user clicks
let lure_links = dynamic(["theshortner.com","suppertools.com","healthscratches.com"]);
EmailUrlInfo
| where Url has_any (lure_links) or Url matches regex @"(?i)https?://[^/]*\.(short|shortner|link)"
| join kind=inner (EmailEvents | where AttachmentCount > 0) on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, Url, NetworkMessageId
| join kind=leftouter (
    UrlClickEvents
    | project ClickTime=TimeGenerated, Url, AccountUpn, ActionType, IPAddress
  ) on Url
| project TimeGenerated, RecipientEmailAddress, Subject, Url, ClickTime, ActionType
```

Pivot clicked URLs into proxy logs: follow the redirect chain (`referer`) to any `application/x-rar`/`application/zip` download or credential-page landing on the same host within ~30 min of `ClickTime`.

## Triage guidance

- **Likely malicious:** a themed/Arabic-geopolitical or Israeli-authority lure PDF whose only link is a shortener resolving to a <60-day themed domain; a click followed within minutes by a RAR download or a Docdroid-lookalike login page; a redirect chain that behaves differently by source IP (gated).
- **Likely benign / expected:** legitimate marketing/newsletter shorteners, genuine document-sharing (real Docdroid/DocSend), internal link-tracking. Baseline the shorteners and doc-sharing services your org actually uses and suppress; focus on first-seen + themed.
- **Pivot next:** if a click landed a download, pivot straight to LOLBIN/sideload execution on that host (HUNT-03, HUNT-05) and to web C2 (HUNT-08); pivot the redirect terminus and sender to the infrastructure cluster (HUNT-01). If a user reached a credential page and authenticated, treat as a possible account compromise and escalate. Repeatable shortener→themed-domain redirect patterns that survive as durable can go to detection-engineering as a proxy-category rule (they write it, not you).

## References

- https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/
- https://attack.mitre.org/groups/G0090/
