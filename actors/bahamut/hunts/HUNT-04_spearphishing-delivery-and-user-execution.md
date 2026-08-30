# Hunt: Bahamut — spearphishing delivery (link / messaging service / drive-by) & user execution

- **Hypothesis:** If Bahamut is delivering to our people, then because their delivery is **single-use links to credential portals or trojanized-app downloads — pushed by email, over third-party messaging apps (WhatsApp spear-messaging), and via lure-driven drive-by from fake-news/fake-vendor sites** — the observable chain is: an inbound link to a young/look-alike domain reaching an at-risk mailbox, a user *click* on it (URL-click telemetry / proxy), and then either a browse to an app-download/staging host or a portal. Because the highest-value target contact (WhatsApp) is invisible to enterprise telemetry, the hunt must also treat a **first-seen internal browse to a staging/distribution look-alike with no preceding email or web referrer** as the tell-tale of an out-of-band (messaging) delivery. A delivered link alone is thin; a click that lands on a staging/portal look-alike identified in HUNT-02 is the finding.
- **ATT&CK:**
  - T1566.002 — Phishing: Spearphishing Link (initial-access) — primary vector: targeted emails/messages carrying links to credential-harvest pages or trojanized-app downloads, bespoke per victim; hunt via mail-gateway URL detonation + newly-registered-domain reputation.
  - T1566.003 — Phishing: Spearphishing via Service (initial-access) — SafeChat delivered directly over WhatsApp spear-messaging; invisible to enterprise telemetry, so hunt the *download landing* it produces.
  - T1189 — Drive-by Compromise (initial-access) — targets lured to fake-news/fake-vendor sites (and app-store listings) serving trojanized apps/malicious content; hunt via web-proxy telemetry to young look-alike domains.
  - T1204.001 — User Execution: Malicious Link (execution) — compromise depends on the user clicking the attacker link (portal or app download, e.g. thesecurevpn[.]com); hunt via URL-click telemetry.
  - T1608.001 — Stage Capabilities: Upload Malware (resource-development) — trojanized apps staged on attacker distribution sites (thesecurevpn[.]com) and historically smuggled into app stores; hunt via distribution-domain browse activity.

- **Actor procedure:** Bahamut's primary initial access is bespoke spearphishing: emails and messages carrying single-use links either to credential-harvesting portals or to trojanized-app downloads. In the SecureVPN campaign the trojanized SoftVPN/OpenVPN builds were staged on thesecurevpn[.]com (mimicking the real SecureVPN); in the SafeChat/CoverIm campaign the malicious Safe_Chat.apk was delivered person-to-person over WhatsApp spear-messaging. They also lure targets to fake-news and fake-vendor sites where downloads carry a veneer of legitimacy. Compromise always requires the user to click and then install/enter credentials — user execution is the pivot the whole operation depends on.
- **Why a hunt, not a rule:** The delivery domains are single-use and rotate weekly/daily, so a URL/domain blocklist is stale immediately (Level-1 indicators). Worse, the highest-value channel — WhatsApp — produces *no enterprise telemetry at all*, an acknowledged visibility gap, so there is no event to alert on for the most important deliveries. The hunt correlates what we *can* see (a click on a young look-alike, a first-seen browse to a staging host from HUNT-02) with target context (at-risk user, no legitimate referrer) — judgement across mail, proxy and URL-click telemetry. If a specific confirmed distribution/portal domain emerges, promote it to the detection pack's proxy/DNS blocklist (T1071.001); the *out-of-band-delivery-with-no-referrer* pattern stays a hunt.
- **VISIBILITY-GAP NOTE:** WhatsApp/third-party-messaging delivery (T1566.003) is **not observable** in enterprise telemetry — this is a finding in its own right. Cover it with user-awareness for at-risk staff and mobile-threat-defense (see HUNT-06/07), not with a network rule.

## Data sources required

- Mail gateway URL detonation / rewrite logs + inbound message metadata to at-risk mailboxes.
- URL-click telemetry (Safe Links / browser isolation / proxy) — who clicked, when, landing host.
- Web-proxy / secure-web-gateway logs — first-seen browse to young look-alike distribution/portal domains (referrer present vs absent).
- Newly-registered-domain / brand-permutation reputation (shared with HUNT-02); at-risk-user watchlist.

## Query starting point

Platform: `KQL / Microsoft Sentinel (URL clicks fused with young-domain reputation & missing referrer)`

```kusto
let youngdomains = _GetWatchlist('bahamut_lookalike_portals')
    | union (_GetWatchlist('newly_registered_domains'))
    | project BadDomain = Domain;
let atrisk = _GetWatchlist('at_risk_individuals') | project AccountUpn = UPN;
// (a) Clicks on links to young/look-alike domains (Safe Links)
UrlClickEvents
| where TimeGenerated > ago(30d)
| extend Host = tostring(parse_url(Url).Host)
| where Host in (youngdomains)
| where AccountUpn in (atrisk) or true                     // widen if watchlist sparse
| project ClickTime = TimeGenerated, AccountUpn, Url, Host, ActionType
// (b) Corroborate with a proxy browse to a staging host lacking any web/mail referrer (out-of-band delivery tell)
| union (
    DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | extend Host = RemoteUrl
    | where Host in (youngdomains)
    | where isempty(InitiatingProcessCommandLine) or InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
    | project ClickTime = TimeGenerated, AccountUpn = InitiatingProcessAccountName, Url = RemoteUrl, Host, ActionType = "ProxyBrowse"
)
| order by ClickTime desc
```

## Triage guidance

- **Likely malicious:** an at-risk user clicking a link to a young/look-alike domain that HUNT-01/02 already flagged as a portal or distribution site; a first-seen browse to an app-download/staging host with *no* email or web referrer (consistent with a WhatsApp-delivered link); a click immediately preceding an anomalous auth (HUNT-01) or an APK-install/EDR event on the user's mobile (HUNT-06).
- **Likely benign / expected:** users click legitimate newly-registered domains constantly (marketing, new SaaS, news) — young age alone is noise; missing-referrer browses occur from bookmarks and apps; VPN/privacy-app interest among privacy-conscious staff is normal. A click with no look-alike/reputation corroboration and no downstream event is not a finding.
- **Pivot next:** if a click lands on a confirmed portal → HUNT-01 (ATO check + credential reset); if it lands on an app-distribution host → HUNT-06/07 (mobile install + accessibility abuse) and MDM check for sideloaded packages com.secure.vpn / com.openvpn.secure / Safe_Chat.apk. Escalate to incident-response-coordinator if install or credential-entry is confirmed. Push the confirmed delivery domain to the detection pack blocklist.

## References

- https://blogs.blackberry.com/en/2020/10/blackberry-uncovers-massive-hack-for-hire-group-targeting-governments-businesses-human-rights-groups-and-influential-individuals
- https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/
- https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/
- https://attack.mitre.org/techniques/T1566/002/
- https://attack.mitre.org/techniques/T1566/003/
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1608/001/
