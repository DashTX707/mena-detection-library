# Hunt: OilRig alternate initial-access vectors — social-media lures & supply chain

- **Hypothesis:** If OilRig is targeting us outside the corporate mail channel, then evidence will appear off the standard email path — spearphishing links delivered via LinkedIn/social platforms (bypassing the mail gateway), and payloads or access arriving through a trusted third-party supplier — so proxy/DNS, endpoint-download and vendor-connection telemetry will show the delivery even when the email gateway shows nothing.
- **ATT&CK:**
  - T1566.003 — Phishing: Spearphishing via Service (initial-access)
  - T1195 — Supply Chain Compromise (initial-access)
- **Actor procedure:** OilRig **uses LinkedIn to send spearphishing links**, engaging targets over social media where corporate mail controls do not apply, and **leverages compromised organizations to conduct supply-chain attacks** against downstream victims.
- **Why a hunt, not a rule:** social-media-delivered lures never touch the mail gateway, and upstream supply-chain compromise is largely outside victim endpoint visibility — there is no reliable single event to alert on. The hunt correlates user-reported social contact, proxy access to social-platform message links / file shares, and anomalous first-contact traffic from trusted-vendor infrastructure — intel- and awareness-driven analysis.

## Data sources required

- Proxy / web-gateway logs (LinkedIn/Twitter/Telegram message-link and file-share URLs, followed by downloads)
- Endpoint download telemetry (browser-originated file writes to Downloads shortly after a social-platform referrer)
- Vendor/third-party connection inventory + software-update source telemetry (for supply-chain first-contact)
- User-reported phishing / awareness channel

## Query starting point

Platform: `Splunk SPL`

```
(index=proxy OR index=dns)
| eval ref=lower(coalesce(http_referrer,referrer)), url=lower(coalesce(url,dest_host))
| eval social_lure=if(match(ref,"(linkedin|t\.co|twitter|telegram|facebook)\.") AND match(url,"(download|file|share|drive|\.(zip|rar|doc|xls|hta|lnk|iso|img))"),1,0)
| eval vendor_firstseen=if(match(url,"update|patch|repo") AND isnull(mvfind(known_vendor_hosts,url)),1,0)
| where social_lure=1 OR vendor_firstseen=1
| stats count values(url) as urls values(ref) as referrers min(_time) as first by src_ip, user, social_lure, vendor_firstseen
| sort first
```

## Triage guidance

- **Likely malicious:** a download of an archive/HTA/LNK/ISO immediately following a social-media message-link referrer; a target in a high-value role (energy/gov/defense) engaged via LinkedIn then fetching a "job description"/"conference agenda" file; software-update or payload traffic from a supplier host never seen before, close in time to endpoint compromise.
- **Likely benign / expected:** normal recruiting/sales use of LinkedIn; legitimate SaaS file shares; scheduled vendor software updates from known hosts. Baseline known vendors and business social use.
- **Pivot next:** endpoint review of the downloading host (HUNT-09 macro/script lineage, HUNT-03 discovery); confirm whether the file executed; if a supplier is implicated, engage IR/intel for third-party scoping and feed lookalike/social indicators to HUNT-02.

## References

- https://attack.mitre.org/groups/G0049/
