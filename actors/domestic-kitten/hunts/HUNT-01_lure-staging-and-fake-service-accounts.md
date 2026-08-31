# Hunt: Lookalike lure staging sites and fake Telegram service accounts

- **Hypothesis:** If Domestic Kitten / Rampant Kitten is staging FurBall APKs or Telegram phishing on actor-controlled infrastructure, then egress logs will show enterprise users resolving/visiting Persian-language lookalike domains that impersonate a translation service, app store, security product, or Telegram "service" (a masquerading + never-before-seen-domain anomaly), often reached from a Telegram/SMS referral rather than organic search.
- **ATT&CK:**
  - T1608.006 — Stage Capabilities: SEO Poisoning (resource-development)
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development)
- **Actor procedure:** The ESET FurBall campaign staged its malicious APK on `downloadmaghaleh.com`, a copycat of a legitimate Persian scientific-paper translation service, behind a fake Google Play button; other campaigns hosted payloads on Iranian blogs and a MyKet-mimic app store. Rampant Kitten created fake Telegram "service" accounts that messaged targets with bogus "improper use of Telegram" warnings, driving them to credential-phishing pages (`telegramreport.me`, `telegramco.org`, `telegrambots.me`).
- **Why a hunt, not a rule:** The staging sites and messaging accounts are off-victim infrastructure the operators rotate freely, so a static blocklist of the known domains ages out fast and is pure IOC matching (Summiting Level 1). The durable hunt is the behavioral shape — enterprise-referred visits to newly-registered Persian lookalike domains that end in an APK/download prompt, and the referral pattern from a messaging app — which survives domain rotation. Confirmed lookalikes belong to brand-monitoring/takedown, not an endpoint alert.

## Data sources required

- DNS resolver logs (query name, first-seen timestamp, requesting host)
- Web proxy / firewall egress logs (URL, referer, user-agent, bytes, content-type)
- Threat-intel / passive-DNS enrichment (domain age, registrar, WHOIS registrant)
- Brand / lookalike-domain monitoring feed (optional but load-bearing)

## Query starting point

Platform: `Splunk SPL`

```
index=proxy OR index=dns
| eval dom=lower(coalesce(query,url_domain))
| `comment("newly-seen + Persian-lure lexical + Telegram-service impersonation")`
| where match(dom,"(maghaleh|tarjome|translate|market|mservices|myket|vipre|amaq|telegram(report|co|bots|up|backups|desktop))")
   OR like(content_type,"application/vnd.android.package-archive")
| join type=left dom [ | inputlookup passivedns_firstseen.csv ]
| eval age_days=round((now()-first_seen)/86400)
| where age_days < 90 OR isnull(age_days)
| stats count values(url) as urls values(http_referer) as referers
        values(content_type) as ctypes dc(src_ip) as hosts min(age_days) as youngest_age
        by dom
| where hosts <= 25
| sort youngest_age
```

## Triage guidance

- **Likely malicious:** Newly-registered (<90d) Persian lookalike domain impersonating a translation/app-store/security/Telegram brand; the visit ends in an `application/vnd.android.package-archive` download or a Telegram/Google login form; referer is a messaging app or SMS-shortener; Iranian WHOIS registrant or Tehran/Karaj hosting.
- **Likely benign:** Established, correctly-spelled vendor domains; corporate MDM app-catalog fetches over signed channels; long-tenured domains with organic search referers. Baseline the org's normal APK-download sources before flagging.
- **Pivot next:** If a staging domain is confirmed, pivot to HUNT-02 (did any device install the served APK) and sweep DNS for the same registrant/IP infrastructure. Report the lookalike domain and fake Telegram account for takedown; hand the durable "newly-registered-lookalike + APK-download" pattern to detection-engineering if egress visibility is reliable.

## References

- https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/
- https://research.checkpoint.com/2020/rampant-kitten-an-iranian-espionage-campaign/
- https://attack.mitre.org/techniques/T1608/006/
- https://attack.mitre.org/techniques/T1585/001/
