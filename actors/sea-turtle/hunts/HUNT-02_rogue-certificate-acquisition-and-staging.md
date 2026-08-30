# Hunt: Sea Turtle — rogue certificate acquisition and staging for our owned domains

- **Hypothesis:** If Sea Turtle is preparing to man-in-the-middle our services, then before or during the DNS hijack they will obtain a CA-signed X.509 certificate for one of *our* domains and stand it up on their MitM node — so a certificate we never requested will appear in Certificate Transparency (CT) logs for a name we own, typically from Let's Encrypt or Comodo/Sectigo, issued to a CAA/registrar/validation path that does not match our own issuance pipeline, and the live TLS endpoint for that name will subsequently present an issuer/serial/public-key that differs from our authoritative certificate. A lone unexpected CT entry can be a shadow-IT or partner cert; the finding is a CT entry for our name that we cannot map to an internal issuance request, **stacked** with a DNS anomaly on the same name (HUNT-01) or a TLS-fingerprint change observed at the endpoint (HUNT-03).
- **ATT&CK:**
  - T1588.004 — Obtain Capabilities: Digital Certificates (resource-development) — actor acquires a CA-signed (or self-signed) cert for the victim domain so the MitM portal presents a trusted certificate; caught as an unrequested CT issuance for our name.
  - T1608.003 — Stage Capabilities: Install Digital Certificate (resource-development) — actor installs that certificate on the MitM VPS so intercepted TLS sessions look valid; caught as an issuer/serial/key mismatch between the CT record and our authoritative endpoint.

- **Actor procedure:** To defeat browser TLS warnings during credential interception, Sea Turtle obtains valid CA-signed certificates (Let's Encrypt, Comodo/Sectigo observed) — or uses self-signed certs — for the victim's own domains, then installs them on the man-in-the-middle VPS nodes that impersonate the victim's VPN, webmail and login portals. Because the actor briefly controls DNS resolution for the zone (HUNT-01), they can pass domain-validation (DV) challenges and legitimately obtain a DV certificate for a name they do not own. The staged cert makes the spoofed portal appear genuine to victims and to the browser.
- **Why a hunt, not a rule:** Certificate issuance happens at third-party CAs and installation happens on infrastructure we do not control — neither is visible in our host or network telemetry. CT logs give an external vantage, but CT is noisy: CDNs, SaaS vendors, marketing platforms and shadow IT legitimately request certs for our subdomains every day. Distinguishing an actor-staged cert from benign external issuance requires reconciling each CT entry against our *own* record of what we requested — analyst context, not a signature. A durable observable that could later become a detection is "a CT issuance for an owned domain that does not correlate to an entry in our certificate-request ledger"; if we can make that ledger authoritative, hand the reconciliation check to detection-engineering as a monitor. The MitM cert on the wire (T1557/HUNT-03) is where the correlation closes.

## Data sources required

- Certificate Transparency feed for owned domains (crt.sh / Censys / Cert Spotter / CT firehose) — the primary external vantage
- Internal certificate-request ledger / ACME + CA account logs / CAA records — the authoritative "did we ask for this?" baseline
- Endpoint TLS observation (external synthetic checks, TLS-scan, or proxy JA3/JA4 + issuer capture) for owned login/VPN/webmail hostnames
- HUNT-01 DNS anomaly output as the correlating stack

## Query starting point

Platform: `KQL / Microsoft Sentinel` — CT ingestion reconciled against our issuance ledger

```kusto
let owned = _GetWatchlist('owned_domains') | project domain = SearchKey;
let requested = CertRequestLedger_CL                       // our ACME/CA account issuance records
    | project reqName = tolower(CommonName_s), reqIssuer = Issuer_s, reqTime = TimeGenerated;
CertTransparency_CL                                        // ingested CT firehose filtered to our names
| where TimeGenerated > ago(30d)
| extend certName = tolower(CommonName_s)
| where certName in (owned) or certName has_any (owned)
| join kind=leftanti requested on $left.certName == $right.reqName   // CT entry we never requested
| extend suspiciousIssuer = Issuer_s has_any ("Let's Encrypt","Sectigo","Comodo")  // DV, actor-observed
| join kind=leftouter (                                    // corroborate with a DNS anomaly on same name
    Hunt01_DnsAnomaly_CL | project certName = tolower(domain), anomaly_stack
  ) on certName
| project TimeGenerated, certName, Issuer_s, SerialNumber_s, suspiciousIssuer, anomaly_stack
| order by anomaly_stack desc, TimeGenerated desc
```

## Triage guidance

- **Likely malicious:** a DV certificate (Let's Encrypt / Sectigo / Comodo) issued for one of our VPN/webmail/SSO hostnames with no matching entry in our issuance ledger, especially when the live endpoint later presents that issuer/serial and there is a concurrent DNS anomaly (HUNT-01) or resolution to a MitM VPS (HUNT-03) for the same name; a self-signed cert appearing on a name that should be CA-signed.
- **Likely benign / expected:** CDNs (Cloudflare, Akamai), SaaS vendors and email-security gateways request certs for our subdomains as part of normal onboarding; marketing/DX platforms issue Let's Encrypt certs for campaign hostnames; renewals produce new serials for the same name. Reconcile against the ledger, CAA records and known third-party integrations before flagging. A CT entry that maps to an approved vendor or an internal request is normal.
- **Pivot next:** an unreconciled cert for a login portal that time-correlates with a DNS change is MitM staging in progress — escalate to incident-response-coordinator, request CA revocation of the rogue cert, force rotation of credentials exposed during the window, and run HUNT-03 to confirm live interception and HUNT-01 to find/lock the DNS change. Tighten CAA records and enable CT-monitoring alerting on all owned zones.

## References

- https://blog.talosintelligence.com/seaturtle/
- https://attack.mitre.org/techniques/T1588/004/
- https://attack.mitre.org/techniques/T1608/003/
