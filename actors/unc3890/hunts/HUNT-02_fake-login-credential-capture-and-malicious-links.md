# Hunt: UNC3890 — fake-login credential capture via typosquat/brand-spoof links (Israeli dating-service & job-offer lures)

- **Hypothesis:** If UNC3890 is phishing our users toward credential-capture portals, then the on-victim tell is a user endpoint **resolving and browsing an actor typosquat/brand-spoof domain** (lirikedin[.]com / xn--lirkedin-vkb[.]com, rnfacebook[.]com, office365update[.]live, pfizerpoll[.]com, celebritylife[.]news, fileupload[.]shop, naturaldolls[.]store, xxx-doll[.]com, aspiremovecentraldays[.]net) shortly after an inbound email or chat, **followed by an HTTP POST** of form data to that host — and then, hours to days later, an **anomalous successful login** to the *real* spoofed service (O365, LinkedIn) from a new/foreign ASN using the credential the user just typed into the clone. No single leg proves it: the domain resolution is a click, the POST could be a benign form, the foreign login could be travel. Stacked on the same identity in sequence — click a spoof domain, submit a form, then that identity authenticates from impossible-geo — it is a captured-credential replay.
- **ATT&CK:**
  - T1204.001 — User Execution: Malicious Link (execution) — the user clicks a link in a fake job-offer / fake dating-service / spoofed-login email and browses to actor infrastructure; the hunt ties the proxy/DNS resolution of the typosquat domain back to the user who browsed it.
  - T1056.003 — Input Capture: Web Portal Capture (credential-access) — the fake login pages (O365, LinkedIn, Facebook, Pfizer, an Israeli dating service, the shipping watering hole) capture credentials typed into cloned portals; the hunt looks for the form-submission POST to the clone and the downstream anomalous login to the real service.
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — the typosquat/brand-spoof domains are the actor-registered infrastructure the hunt pivots on; treated as expiring pivots, not the hunt's basis.

- **Actor procedure:** UNC3890 ran an elaborate social-engineering effort — fake job offers (a fraudulent NexisLexis/Nexus offer), fake AI/robotics "robotic dolls" commercials, and a link to a fake Israeli dating-service login — driving victims to credential-capture pages that spoofed Office 365, LinkedIn (typosquat lirikedin[.]com, punycode xn--lirkedin-vkb[.]com), Facebook (rnfacebook[.]com — "rn" mimicking "m"), Pfizer (pfizerpoll[.]com) and others, hosted on actor infrastructure (128.199.6.246, 185.170.215.170). Captured credentials fed follow-on access to the victims' real accounts.
- **Why a hunt, not a rule:** Inbound mail-gateway URL-reputation on lookalike domains is already a *detection* (routed to the detect lane as T1566.002) — re-flagging known-bad domains here would be QA of that rule, not hunting. The hunt's value is the part a rule can't close: correlating a domain visit with a *form submission* and then with a *later anomalous authentication to the genuine service*, across three telemetry islands (proxy, DNS, IdP sign-in logs) and a multi-day gap. The individual legs are low-fidelity and the domains are Summiting Level 1 IOCs that rotate; the durable, hunt-worthy pattern is the behavioral chain "spoof-domain form POST → impossible-geo login on the same identity" — a relationship the actor can't avoid while phishing for credentials. If that chain proves repeatable and precise, the impossible-geo-after-credential-submission half is a candidate to hand to detection-engineering.

## Data sources required

- DNS resolver + web proxy logs (domain, full URL, HTTP method, user, Referer) — resolution of and POST to the typosquat domains
- Email gateway logs (sender, subject, embedded URLs) — to tie the click back to the delivering lure
- Identity provider sign-in logs (Azure AD / Okta): O365, LinkedIn SSO, VPN — successful auth, source IP/ASN, geo, device
- Newly-registered-domain (NRD) and brand/typosquat monitoring feed — to widen beyond the known IOC set to *lookalikes of our own brand*
- Threat-intel watchlist of the known UNC3890 spoof domains

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — chain a spoof-domain POST to a later impossible-geo sign-in on the same user

```kusto
let spoofDomains = dynamic(["lirikedin.com","xn--lirkedin-vkb.com","rnfacebook.com",
  "office365update.live","pfizerpoll.com","celebritylife.news","fileupload.shop",
  "naturaldolls.store","xxx-doll.com","aspiremovecentraldays.net"]);
// (a) user submitted a form to an actor spoof domain
let capture = _Im_WebSession(starttime=ago(30d))
    | where Url has_any (spoofDomains)
    | where HttpRequestMethod == "POST" or Url has_any ("login","signin","auth")
    | project User=SrcUserName, Device=DstHostname, spoofUrl=Url, tCapture=TimeGenerated;
// (b) that same user later authenticates to a real service from an unusual location
let anomLogin = SigninLogs
    | where TimeGenerated > ago(30d) and ResultType == 0
    | where AppDisplayName has_any ("Office 365","LinkedIn","VPN","Outlook")
    | extend User = tolower(UserPrincipalName)
    | project User, loginIp=IPAddress, loginCity=tostring(LocationDetails.city),
              asn=tostring(AutonomousSystemNumber), tLogin=TimeGenerated;
capture
| extend User = tolower(User)
| join kind=inner (anomLogin) on User
| where tLogin between (tCapture .. tCapture + 7d)      // replay window
| summarize spoofUrls=make_set(spoofUrl), logins=make_set(strcat(loginCity,"/",asn)),
            firstCapture=min(tCapture), lastLogin=max(tLogin) by User
| order by lastLogin desc
```

## Triage guidance

- **Likely malicious:** a user who POSTed to one of the spoof domains and then successfully authenticated to the matching real service (LinkedIn after lirikedin[.]com; O365 after office365update[.]live) from a never-before-seen ASN/country, especially an Iran-nexus or hosting-provider IP; several employees converging on the same spoof domain from the same lure email; a punycode domain (xn--lirkedin-vkb[.]com) rendering as a brand in the browser bar. The capture-then-foreign-login sequence on one identity is the strong signal.
- **Likely benign / expected:** legitimate travel or VPN producing a new-geo login with no preceding spoof-domain POST; users browsing an unrelated dating/shopping site that merely *resembles* an actor domain — confirm the exact FQDN, not a keyword; security-awareness phishing-simulation platforms that host lookalike domains for training (baseline and exclude); a form POST to a spoof domain that the browser's password manager *refused* to autofill (a tell the user typed, but also common on legitimate new sites). A domain visit with no POST and no downstream anomalous login is inconclusive — park it.
- **Pivot next:** if capture-then-replay is confirmed, this is a live account compromise — escalate to incident-response-coordinator, force-reset the credential on every service the user reused it for, revoke active sessions/tokens, and pivot to HUNT-01 (did they arrive via the watering hole?) and the detection pack (T1539 cookie theft, T1555.003). Pull the delivering lure email and sweep all recipients. Feed the confirmed spoof FQDNs and any newly-surfaced lookalikes of *our own brand* to brand-monitoring and the mail gateway.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping
- https://www.securityweek.com/iranian-group-targeting-israeli-shipping-and-other-key-sectors/
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1056/003/
- https://attack.mitre.org/techniques/T1583/001/
