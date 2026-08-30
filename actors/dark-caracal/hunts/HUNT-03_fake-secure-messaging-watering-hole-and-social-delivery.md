# Hunt: Dark Caracal — fake secure-messaging watering-hole & social-service delivery infrastructure (off-victim/social)

- **Hypothesis:** Dark Caracal's initial access against high-risk staff (journalists, lawyers, activists, defense/government contacts) does not come through corporate email — it comes through a fake secure-messaging watering-hole site and social-service lures (Facebook groups/pages, WhatsApp messages) that push trojanized "secure messaging" apps (WhatsApp/Signal/Telegram/Primo look-alikes carrying Pallas). If the actor is targeting our people, then the tell is off enterprise endpoint telemetry and must be reconstructed from the edges: web-filter/DNS hits from managed devices to a newly-stood-up "download our secure messenger" site impersonating a known brand, brand/persona-monitoring hits on Dark-Caracal-style Facebook/WhatsApp delivery personas, and user-reported "I was asked to install a secure chat app via Facebook/WhatsApp." Each alone is thin; a brand-impersonation download site that our targeted staff are steered to *via a social service* is the finding.
- **ATT&CK:**
  - T1608.004 — Stage Capabilities: Drive-by Target (resource-development) — the adversary-controlled fake secure-messaging site staged to distribute trojanized Android apps; hunt via infrastructure tracking + web-filter hits to look-alike download pages
  - T1566.003 — Phishing: Spearphishing via Service (initial-access) — Facebook groups/pages and WhatsApp used to social-engineer targets toward the malicious site/app; hunt via brand/persona monitoring and user reporting
  - T1189 — Drive-by Compromise (initial-access) — targets who browse to the watering-hole are served the trojanized app; hunt via web-filtering and mobile-threat-defense on managed/enrolled devices

- **Actor procedure:** In the 2018 operation Dark Caracal stood up a fake secure-messaging watering-hole site to distribute trojanized copies of popular messaging and utility apps (Pallas builds impersonating WhatsApp, Signal, Telegram, Primo). Targets were steered to the site and to malicious content through social engineering on third-party services — Facebook groups and pages, and direct WhatsApp messages — rather than through enterprise email, deliberately keeping delivery off corporate mail-security telemetry. The lure is a trust play: "install this more-secure version of the messenger you already use." This is the classic mercenary-surveillance pattern of targeting individuals (dissidents, journalists, lawyers, military personnel) rather than networks.
- **Why a hunt, not a rule:** The delivery surface is Facebook, WhatsApp and an external website — none of which produce enterprise alerts. There is no email gateway to fire, no endpoint process to catch at the delivery moment. The signal has to be assembled from partial edges: a web-filter/DNS hit to a look-alike download domain, an infrastructure-tracking match on the site's registration (feeds from HUNT-01), a brand-monitoring alert on an impersonating Facebook page/persona, and a human report from a targeted employee. Correlating those weak, cross-channel signals — and judging whether they name *our* people — is intelligence/hunt work, not a deployable rule. Where a durable observable emerges (a confirmed look-alike download domain), promote it to a web-filter/DNS block via detection-engineering; you cannot "alert on a Facebook message."

## Data sources required

- Web-proxy / DNS / secure-web-gateway logs from managed devices: requests to newly-registered brand-impersonation download domains ("secure messenger download", `whatsapp`/`signal`/`telegram`/`primo` look-alike strings in host/URI)
- Brand-protection / social-media monitoring: impersonating Facebook pages/groups, personas, and WhatsApp numbers pushing "secure app" installs referencing your org, region (Lebanon/MENA) or high-risk staff
- User-report / abuse mailbox and security-awareness reporting: "someone on Facebook/WhatsApp asked me to install a secure messaging app"
- Domain-infrastructure intel (shared with HUNT-01): registrar/TLD clustering to identify the distribution site before it is heavily used

## Query starting point

Platform: `Splunk SPL` — surface managed-device web hits to messaging-brand look-alike download pages that do not resolve to the real vendors.

```spl
index=proxy OR index=dns sourcetype=* earliest=-30d
| eval host_l=lower(coalesce(url_domain,query,dest_host))
``` look for messaging-brand tokens paired with download/install intent ```
| where (like(host_l,"%whatsapp%") OR like(host_l,"%signal%") OR like(host_l,"%telegram%")
        OR like(host_l,"%primo%") OR like(host_l,"%securechat%") OR like(host_l,"%messenger%"))
``` exclude the real vendor infrastructure (baseline/allowlist) ```
| search NOT host_l IN ("*.whatsapp.com","*.whatsapp.net","*.signal.org","*.telegram.org",
                        "*.t.me","web.whatsapp.com")
| eval looks_like_download=if(match(url,"(?i)(apk|download|install|setup|update)"),1,0)
| stats count, dc(src_ip) as devices, values(url) as urls, min(_time) as first, max(_time) as last
        by host_l looks_like_download
| where looks_like_download=1
| convert ctime(first) ctime(last)
| sort - first
```

## Triage guidance

- **Likely malicious:** a managed device resolving/visiting a newly-registered domain that impersonates a messaging brand and serves an APK or "install our secure version" page, especially if the domain matches the HUNT-01 registrar/TLD cluster; a brand-monitoring hit where a Facebook persona or WhatsApp number is steering *your named high-risk staff* to such a site; a user report of a social-service lure that corroborates a web-filter hit on the same domain/timeframe.
- **Likely benign / expected:** legitimate use of the real WhatsApp/Signal/Telegram web and download domains; help-desk or MDM pushing sanctioned messaging apps; security researchers browsing to a reported malicious site (baseline researcher egress); generic "messenger" SaaS unrelated to the impersonated brands.
- **Pivot next:** confirmed look-alike distribution domain → feed it to HUNT-01 infrastructure clustering and to detection-engineering for a web-filter/DNS block; identify which staff visited (web-filter src), and check enrolled mobile devices for a sideloaded impersonating app (pivot to HUNT-04). If a targeted employee actually installed, escalate to incident-response-coordinator and initiate mobile-device compromise handling — this actor collects SMS, contacts, call logs, location, audio and photos from Pallas-infected phones.

## References

- https://www.lookout.com/documents/reports/lookout-dark-caracal-20180118-us.pdf
- https://www.eff.org/deeplinks/2020/12/dark-caracal-you-missed-spot
- https://attack.mitre.org/groups/G0070/
- https://attack.mitre.org/techniques/T1608/004/
- https://attack.mitre.org/techniques/T1566/003/
- https://attack.mitre.org/techniques/T1189/
