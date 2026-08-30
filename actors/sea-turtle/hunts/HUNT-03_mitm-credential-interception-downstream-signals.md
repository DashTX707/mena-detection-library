# Hunt: Sea Turtle — adversary-in-the-middle credential interception (downstream on-victim signals)

- **Hypothesis:** The interception itself runs on the actor's off-victim MitM node, but it leaves *downstream* fingerprints we can see. If Sea Turtle is transparently proxying our users through a MitM portal, then for a spoofed service (VPN concentrator, webmail, SSO) three things co-occur: (1) our clients resolve the service to an unexpected IP — one of the documented MitM VPS addresses rather than our real endpoint; (2) the live TLS certificate/issuer/JA3-JA4 fingerprint presented for that name changes without a corresponding internal cert rotation; and (3) a short time later, credentials captured at the MitM are replayed against the *real* service, producing anomalous authentications — logons from actor/VPN-provider source IPs, impossible travel, or first-seen-device events for accounts whose users never left. Interposing a spoofed login portal into the auth flow (T1556) and capturing the credentials in transit (T1557) is a single operation; the hunt fuses the resolution/TLS anomaly with the credential-replay anomaly on the same account/service. Either half alone is weak; the pair is the finding.
- **ATT&CK:**
  - T1557 — Adversary-in-the-Middle (credential-access) — actor transparently proxies victim traffic through a MitM node presenting a valid cert to capture submitted credentials; surfaces as unexpected resolution IP + TLS-fingerprint change for owned services.
  - T1556 — Modify Authentication Process (credential-access) — actor interposes a spoofed login portal into the legitimate authentication flow; surfaces downstream as impossible-travel / new-source-IP authentications from harvested credentials.

- **Actor procedure:** After hijacking DNS (HUNT-01) and staging a valid certificate (HUNT-02), Sea Turtle routes victim traffic through actor-controlled MitM VPS nodes that impersonate the victim's VPN, webmail and other login portals. The nodes present a CA-signed cert so the browser shows no warning, harvest the submitted username/password, then relay the session onward to the real service so the user experiences a normal login. The harvested credentials are subsequently reused (T1078) to authenticate directly to victim systems, often from commercial VPN-provider IP space (M247, Arelion, Snel.com observed) or the documented actor IPs.
- **Why a hunt, not a rule:** The credential theft happens between the client and the real service on infrastructure we do not own — no host or app log records the interception. What we *can* see is indirect and individually low-fidelity: client-side resolution telemetry (which many orgs don't centralize), an external TLS-fingerprint check, and anomalous-logon analytics that fire constantly on a mobile workforce. None is reliable alone; the judgement is in correlating a resolution/TLS anomaly for a specific service with a burst of anomalous authentications against that same service shortly after. If a durable relational observable emerges — e.g. "successful logon whose credential was submitted to a hostname that resolved outside our authoritative IP set" — that is worth handing to detection-engineering; the fused, contextual version is hunt work here.

## Data sources required

- Client/recursive DNS resolution logs (endpoint DNS, internal resolver) for owned service hostnames — to catch resolution to a MitM IP
- External TLS/issuer + JA3/JA4 monitoring of owned login/VPN/webmail endpoints (shares CT output with HUNT-02)
- Identity/auth analytics: VPN, webmail, SSO/IdP sign-in logs (impossible travel, new source IP/ASN, first-seen device)
- Threat-intel list of documented MitM VPS IPs and actor/VPN-provider ranges

## Query starting point

Platform: `KQL / Microsoft Sentinel` — resolution/TLS anomaly fused with post-interception sign-in anomalies

```kusto
let mitm = _GetWatchlist('sea_turtle_mitm_ips');           // 26 Talos MitM IPs + 82.102.19.88, 95.179.150.101, ...
// (a) our clients resolving an owned service to a MitM IP
let badResolve = DnsEvents
    | where TimeGenerated > ago(14d)
    | where Name has_any (_GetWatchlist('owned_service_fqdns'))   // vpn., webmail., sso.
    | where IPAddresses has_any (mitm)
    | project resolveTime = TimeGenerated, svc = Name, mitmIp = IPAddresses, Computer;
// (b) anomalous sign-ins to those same services shortly after
let badAuth = SigninLogs
    | where TimeGenerated > ago(14d)
    | where ResultType == 0
    | where RiskState in ("atRisk","confirmedCompromised")
        or IPAddress in (mitm)
        or RiskDetail has_any ("impossibleTravel","unfamiliarFeatures","newCountry")
    | project authTime = TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, RiskDetail;
badResolve
| join kind=inner (badAuth) on $left.svc == $right.AppDisplayName    // same service
| where authTime between (resolveTime .. (resolveTime + 6h))         // replay shortly after interception
| project svc, Computer, mitmIp, resolveTime, UserPrincipalName, IPAddress, RiskDetail, authTime
```

## Triage guidance

- **Likely malicious:** an owned VPN/webmail/SSO hostname resolving to a documented MitM VPS IP; a TLS issuer/fingerprint change for that name unmatched by an internal rotation (HUNT-02); credentials for users who never traveled succeeding from actor/VPN-provider IPs shortly after; a cluster of impossible-travel logons to one portal within hours of a DNS or cert anomaly on that portal's name.
- **Likely benign / expected:** split-horizon DNS, geo-load-balancing and CDN fronting legitimately resolve service names to varied IPs — baseline the authoritative set; corporate VPN and roaming users routinely trip impossible-travel and new-ASN analytics; security scanners and synthetic monitors log in from cloud IPs. A resolution or a risky sign-in *alone*, without the paired anomaly on the same service, is expected noise.
- **Pivot next:** confirmed resolution to a MitM IP with paired credential replay is active interception — escalate to incident-response-coordinator, force-rotate credentials for every account that authenticated to the affected portal during the exposure window, revoke sessions/tokens, require re-MFA, and run HUNT-01/HUNT-02 to close the DNS change and revoke the rogue cert. Add the confirmed MitM IPs to blocklists and preserve resolver + sign-in logs as evidence.

## References

- https://blog.talosintelligence.com/seaturtle/
- https://www.huntandhackett.com/blog/turkish-espionage-campaigns
- https://attack.mitre.org/techniques/T1557/
- https://attack.mitre.org/techniques/T1556/
