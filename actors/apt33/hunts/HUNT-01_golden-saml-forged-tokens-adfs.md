# Hunt: APT33 / Peach Sandstorm Golden SAML & forged federation tokens

- **Hypothesis:** If Peach Sandstorm has compromised our AD FS token-signing certificate, then it can forge SAML tokens to authenticate to federated cloud services as arbitrary users while bypassing MFA — and we should observe the tell-tale *absence of a matching authentication event*: cloud (Entra ID) sign-ins whose federated `AuthnContext`/issuer indicates AD FS but with **no corresponding AD FS 1200/1202 token-issuance event** on the AD FS servers, plus access to or export of the token-signing certificate/private key, and SAML assertions with anomalous lifetimes, `NotBefore`/`NotOnOrAfter` windows or unusual claims/`InResponseTo` values.
- **ATT&CK:**
  - T1606.002 — Forge Web Credentials: SAML Tokens (credential-access) — **flagship**

- **Actor procedure:** As Peach Sandstorm (Microsoft, 2023), APT33 conducted Golden SAML attacks against AD FS servers — using a compromised token-signing certificate to forge SAML tokens and authenticate to federated cloud services (M365 / Entra ID) as any user, bypassing MFA and the on-prem sign-in path entirely. The forgery happens off the identity provider, so the token *looks legitimate* to the relying party; the discriminating evidence is the missing IdP-side issuance record and certificate access on the AD FS host.
- **Why a hunt, not a rule:** A forged token is by design indistinguishable from a real one at the point of use — there is no malformed field to alert on, so this cannot be a single high-fidelity rule. The signal is *relational and requires correlation across two log sources* (cloud sign-ins vs. AD FS issuance) plus a per-user/per-app federation baseline, and the "no matching AD FS event" join is noisy where logging is incomplete (PRT/seamless SSO, guest/B2B, service-principal flows legitimately lack a 1:1 AD FS event). Certificate-access and token-lifetime anomalies are judgement-heavy and low-volume. This is specialist correlation work → hunt. The durable observable — token-signing-cert access on the AD FS host (a Level-4 implementation-core event the actor cannot skip) — can be handed to detection-engineering as an alert once baselined.

## Data sources required

- Entra ID / M365 sign-in logs (federated sign-ins, `AuthenticationDetails`, issuer, token lifetime, correlation IDs)
- AD FS admin/audit + Security logs (Event ID 1200/1202 token issuance, 4662 on the AD FS service account, certificate export)
- AD FS host Sysmon (EID 1 process, EID 10 process access to `Microsoft.IdentityServer.*`, EID 11/18 access to the private key store / DKM container in AD)
- Windows Security 4662/5136 on the AD FS DKM (Distributed Key Manager) object in AD DS

## Query starting point

Platform: `KQL / Microsoft Sentinel` — federated cloud sign-ins with no matching AD FS issuance, plus token-signing-cert access

```kusto
// (a) Cloud sign-ins claiming AD FS federation with NO matching AD FS token-issuance event
let adfsIssued =
    SecurityEvent
    | where EventID in (1200, 1202)          // AD FS token issued / requested
    | project adfsTime = TimeGenerated, Account, CorrelationId = tostring(extract(@"([0-9a-f-]{36})", 1, EventData));
SigninLogs
| where ResultType == 0
| where tostring(parse_json(tostring(AuthenticationDetails))) has "federat"
     or tostring(AuthenticationRequirementPolicies) has "adfs"
| extend uaTime = TimeGenerated
| join kind=leftanti adfsIssued on $left.UserPrincipalName == $right.Account   // <-- no IdP-side record
| project uaTime, UserPrincipalName, AppDisplayName, IPAddress, UserAgent, AutonomousSystemNumber
| order by uaTime desc

// (b) Token-signing-certificate / DKM access on the AD FS host (durable observable)
// Sysmon | where EventID in (10,11,18)
//   and TargetObject has_any ("ADFS\\","CryptoKeys","Microsoft.IdentityServer","DKM")
//   and Image !endswith "\\Microsoft.IdentityServer.ServiceHost.exe"
```

## Triage guidance

- **Likely malicious:** a successful federated cloud sign-in with no matching AD FS 1200/1202 issuance for that user/window; SAML tokens with unusually long lifetimes or hand-set `NotBefore`/`NotOnOrAfter`; access to the token-signing private key / DKM object by a process or account that is not the AD FS service; certificate export events on the AD FS server; forged-token sign-ins correlated with TOR/`go-http-client` access (see HUNT-03 / detection pack T1090.003).
- **Likely benign / expected:** PRT-based seamless SSO, guest/B2B, and service-principal sign-ins legitimately lack a 1:1 AD FS event — enrich and exclude these classes; scheduled AD FS certificate auto-rollover (`AutoCertificateRollover`) touches the signing cert on a known cadence; backup/monitoring agents may read cert stores. Baseline normal federation flows per app before flagging.
- **Pivot next:** if forgery is indicated, treat the AD FS server as compromised — hunt LSASS/registry credential access on it (HUNT-04), pull all sign-ins issued by the suspect certificate, force token-signing-cert rotation (twice) and revoke sessions. Confirmed Golden SAML is a live identity-compromise incident → escalate to IR immediately.

## References

- https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/
- https://attack.mitre.org/techniques/T1606/002/
- https://attack.mitre.org/groups/G0064
