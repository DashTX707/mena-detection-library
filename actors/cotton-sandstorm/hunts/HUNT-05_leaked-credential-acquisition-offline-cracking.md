# Hunt: Cotton Sandstorm leaked-credential acquisition & offline password cracking

- **Hypothesis:** If ASA has acquired leaked datasets and cracked hashes belonging to our users offline, then although the acquisition and cracking are off-victim, their downstream shadow is huntable at our authentication surface: our corporate/personal-account credentials appearing in breach corpora, followed by low-and-slow *successful* authentications reusing those exact credentials from anonymizing infrastructure, with no preceding failed-guessing noise (because the password was pre-cracked, not guessed). The hunt keys on the mismatch between "credential known to be in a public dump" and "clean successful login from a new geo/ASN".
- **ATT&CK:**
  - T1650 — Acquire Access (resource-development)
  - T1110.002 — Brute Force: Password Cracking (credential-access)

- **Actor procedure:** ASA acquires previously-leaked datasets of account credentials from online resources such as `ghostproject[.]fr`, reusing them against targets and to enrich victim profiling (T1650). Where it obtains password *hashes*, it cracks them offline using online services `crackstation[.]net`, `hashes[.]com` and `md5hashing[.]net` (T1110.002). Both activities occur entirely on attacker/third-party resources with no victim-side telemetry; the point at which they become observable is the *reuse* of the recovered plaintext against victim accounts — which looks like a normal successful login, not a brute-force burst.
- **Why a hunt, not a rule:** The acquisition and cracking leave zero defender-side telemetry — there is nothing to alert on off-victim. Downstream, credential *reuse* of a pre-cracked password is deliberately quiet: a single clean success, no lockout, no failure spray, so a brute-force rule (detection pack T1110.001) never fires. The discriminating signal is *relational and stacked*: this account's credential is in a known dump AND it just authenticated cleanly from a never-before-seen geo/ASN (often commercial VPN) AND without the failed attempts that precede guessing. Correlating breach-corpus membership against auth telemetry is intel-plus-judgement work, not a rule.

## Data sources required

- Breach-corpus / credential-dump monitoring (HaveIBeenPwned, dark-web/paste feeds) for corporate and high-risk-personal emails
- Authentication logs (Azure AD / Okta / VPN / OWA / admin panels) — successful logins with source IP, ASN, geo
- Commercial-VPN and hosting ASN reputation (overlap HUNT-03)
- Password-hash exposure awareness (any prior hash leak of our directory/app databases)
- HR / exec-protection roster of high-risk roles

## Query starting point

Platform: `Splunk SPL` — successful login by an account whose credential is in a known dump, from a new/anonymized source, without preceding failures

```
index=auth action=success
| lookup breach_corpus.csv user OUTPUT breach_name breach_date   ` accounts known to be in a public dump `
| where isnotnull(breach_name)
| iplocation src_ip
| lookup commercial_vpn_asn.csv asn OUTPUT vpn_provider
` did this same account have failed attempts in the 24h before success? (guessing) or a clean success (pre-cracked)? `
| join type=left user [ search index=auth action=failure earliest=-24h
                        | stats count AS fail_count by user ]
| eval fail_count=coalesce(fail_count,0)
| where fail_count=0 AND (isnotnull(vpn_provider) OR Country!="<home_country>")
| table _time user src_ip asn vpn_provider Country breach_name breach_date fail_count app
| sort - _time
```

Companion (intel-side): monitor `ghostproject`-class dump feeds and paste sites for our domains; for any newly-dumped credential, force a reset before the reuse window and add the account to a watch.

## Triage guidance

- **Likely malicious:** a clean successful login (no preceding failures) from a commercial-VPN/hosting ASN or an infeasible geo, on an account whose exact credential is present in a recent public dump; a cluster of such logins across multiple dumped accounts in a short window; reuse timed shortly after a fresh dump appeared. This is credential-reuse of pre-cracked plaintext.
- **Likely benign / expected:** users who legitimately travel or use a VPN and successfully authenticate with MFA; accounts in old breaches whose passwords were long since rotated; SSO/token refreshes that appear as successes. Suppress accounts with enforced MFA + verified device, and accounts whose dumped password predates a confirmed reset.
- **Pivot next:** force-reset any account with a dump hit and a matching clean-login anomaly, revoke sessions/tokens, and verify MFA integrity (detection pack T1078 valid-accounts, and the identity pack for MFA-fatigue). Correlate the source ASN back to HUNT-03 infrastructure clustering. A confirmed reuse login into a sensitive/admin service is a live intrusion → escalate to IR. The "dumped-credential + clean-login-from-new-ASN" correlation, once operationalized against a maintained breach feed, is a candidate to hand to detection-engineering.

## References

- https://www.ic3.gov/CSA/2024/241030.pdf
- https://attack.mitre.org/techniques/T1650/
- https://attack.mitre.org/techniques/T1110/002/
