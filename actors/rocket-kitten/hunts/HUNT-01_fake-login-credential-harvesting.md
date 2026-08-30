# Hunt: Rocket Kitten — fake-login credential harvesting and post-theft account abuse

- **Hypothesis:** If Rocket Kitten is running its Thamar-Reservoir-style credential-harvesting playbook against our people, then the on-victim tell is *not* the harvesting page (that lives on the actor's phishing server, off our telemetry) but the pair of (a) a targeted user's browser or mail-URL-rewrite touching a look-alike webmail/portal login domain reached from a spear-phishing message, followed within hours-to-days by (b) an *anomalous* successful authentication to that same account — impossible travel, a never-before-seen device/ASN, or a legacy/basic-auth protocol — from infrastructure the user has no business logging in from. Either half alone is thin (users mistype domains; travel produces odd logons); the credential-theft-then-reuse *sequence on the same identity* is the finding.
- **ATT&CK:**
  - T1598.003 — Phishing for Information: Spearphishing Link (reconnaissance) — the spear-phishing link to the fake-login page; hunted as mail-URL/proxy traffic to look-alike login domains.
  - T1056.003 — Input Capture: Web Portal Capture (credential-access) — the spoofed webmail/portal sign-in form captures the password; hunted post-hoc via anomalous authentication with the harvested credential.

- **Actor procedure:** Per ClearSky's *Thamar Reservoir* and Check Point's *9 Lives*, Rocket Kitten operates a dedicated phishing server hosting fake-login pages that spoof webmail and institutional portal sign-in forms, linked from tailored spear-phishing messages (often after rapport-building — in one case attackers replied in Hebrew to vouch for an email's authenticity). Targets are scholars, scientists, journalists and human-rights activists. Captured credentials feed account compromise: mailbox access, reading correspondence, and harvesting genuine documents reused as lures. The group made only minimal changes to its phishing domains even after public exposure, so look-alike-domain and post-theft-auth analytics stay useful across their campaigns.

- **Why a hunt, not a rule:** The credential capture happens on attacker-hosted pages entirely outside our telemetry — there is no event on our estate to alert on at theft time. What *is* visible (a click to a look-alike login domain; an odd but successful logon) is individually low-fidelity: users legitimately visit new SaaS logins and travel. The value is in correlating the mail-URL/proxy hit against a *specific* targeted user with a *subsequent* anomalous auth on that same identity — a judgement-and-context join across mail, proxy and identity logs, not a single deterministic condition. If a durable, precise pairing falls out (e.g. successful auth from an ASN that first appeared minutes after a rewritten-URL click to a newly-registered look-alike domain), hand *that* scoped correlation to detection-engineering; do not alert on "someone visited a login page."

## Data sources required

- Mail security URL-rewrite / click-tracking logs (Defender for Office 365 `UrlClickEvents`, Proofpoint TAP, Mimecast) — who clicked which link.
- Web proxy / DNS logs — outbound requests to look-alike webmail/portal login hosts, newly-registered / low-reputation domains.
- Identity provider sign-in logs (Entra ID `SigninLogs` / `AADNonInteractiveUserSignInLogs`, ADFS, Okta) — impossible travel, new device/ASN, legacy-auth protocols.
- Targeted-user watchlist (academics, journalists, dissident-liaison, policy/defense staff) to weight the hunt toward the population Rocket Kitten actually pursues.

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR + Entra ID)` — join a click on a look-alike login link to a later anomalous sign-in for the same user.

```kusto
let lookalikeClicks =
    UrlClickEvents
    | where TimeGenerated > ago(30d)
    | where isnotempty(Url)
    // look-alike login lures: login/webmail/sso keywords on non-corporate, often newly-seen hosts
    | where Url has_any ("login","signin","sso","webmail","owa","portal","account","verify")
    | extend host = tostring(parse_url(Url).Host)
    | where host !endswith "ourcompany.com" and host !endswith "microsoftonline.com"
    | project clickTime = TimeGenerated, AccountUpn, host, Url;
let anomalousAuth =
    SigninLogs
    | where TimeGenerated > ago(30d)
    | where ResultType == 0                                   // successful only
    | where RiskLevelDuringSignIn in ("high","medium")
          or ClientAppUsed has_any ("IMAP","POP","SMTP","Other clients")   // legacy/basic auth
    | project authTime = TimeGenerated, AccountUpn = UserPrincipalName,
              IPAddress, Location = tostring(LocationDetails.countryOrRegion),
              ClientAppUsed, RiskLevelDuringSignIn, autonomousSystemNumber;
lookalikeClicks
| join kind=inner anomalousAuth on AccountUpn
| where authTime between (clickTime .. clickTime + 7d)        // theft precedes reuse
| project AccountUpn, host, Url, clickTime, authTime, IPAddress, Location, ClientAppUsed, RiskLevelDuringSignIn
| order by authTime asc
```

## Triage guidance

- **Likely malicious:** a targeted-watchlist user clicks a rewritten link to a newly-registered look-alike webmail/portal host, then within days authenticates successfully from a new country/ASN or over legacy IMAP/POP; the same session immediately reads/downloads mailbox contents or creates an inbox forwarding rule; multiple watchlist users converge on the *same* look-alike host.
- **Likely benign / expected:** legitimate travel and new personal devices produce impossible-travel logons — baseline each user's normal countries/ASNs and known devices; users click genuine new SaaS logins (conference portals, publisher sites) whose names superficially match "login/portal"; password-manager autofill and corporate SSO federation generate benign redirect chains. A click with no subsequent anomalous auth is not a finding; an anomalous auth with no preceding lure click is a *separate* thread, not this one.
- **Pivot next:** confirm mailbox activity post-auth (inbox rules, mass reads, sent lures to other staff — cross to HUNT-02 persona/impersonation); pull the look-alike domain's WHOIS/registration age and hosting (cross to HUNT-04 infrastructure); if genuine documents were exfiltrated or the account sent onward lures, this is an active compromise — escalate to incident-response-coordinator and force-reset the credential plus revoke sessions/tokens.

## References

- https://www.clearskysec.com/thamar-reservoir/
- https://blog.checkpoint.com/research/rocket-kitten-a-campaign-with-9-lives/
- https://attack.mitre.org/techniques/T1598/003/
- https://attack.mitre.org/techniques/T1056/003/
