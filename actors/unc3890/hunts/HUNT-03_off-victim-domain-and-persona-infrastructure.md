# Hunt: UNC3890 — off-victim resource development (spoof domains & webmail personas)

- **Hypothesis:** If UNC3890 is *currently* standing up infrastructure to target our sector, then the earliest, off-victim tell precedes any endpoint compromise: **newly-registered domains that typosquat our own brand or our maritime/sector partners**, sharing the registrar/nameserver/hosting/TLS fingerprints of the known UNC3890 estate, and **actor webmail personas** (the "john.macperson" / "john.macperson2021" identity across yandex/yahoo/gmail/protonmail) appearing as senders into our mail flow or as SMTP-exfil destinations. This is an intel-driven, external-first hunt: the finding is an infrastructure/persona match corroborated by *any* touch of our estate (an inbound mail from the persona, a user resolving a fresh brand-lookalike, an outbound SMTP toward those mailboxes). Registration alone is off-victim intel; registration + a touch of our telemetry is the finding.
- **ATT&CK:**
  - T1583.001 — Acquire Infrastructure: Domains (resource-development) — UNC3890 registered typosquat/brand-spoof domains (lirikedin[.]com, rnfacebook[.]com, office365update[.]live, pfizerpoll[.]com, naturaldolls[.]store, aspiremovecentraldays[.]net); the hunt tracks their pivots and any lookalikes of *our* brand sharing the same infrastructure fingerprints.
  - T1585.002 — Establish Accounts: Email Accounts (resource-development) — UNC3890 established free webmail accounts under the john.macperson / john.macperson2021 persona (yandex/yahoo/gmail/protonmail) used as SUGARDUMP SMTP exfil senders/recipients; the hunt watches mail flow and egress for those mailboxes.

- **Actor procedure:** UNC3890 registered a cluster of typosquatting/brand-spoof domains for watering-hole, fake-login and lure use — LinkedIn (lirikedin[.]com, punycode xn--lirkedin-vkb[.]com), Facebook (rnfacebook[.]com), Office 365 (office365update[.]live), Pfizer (pfizerpoll[.]com), plus celebritylife[.]news, fileupload[.]shop, naturaldolls[.]store, xxx-doll[.]com (robotic-dolls lure) and aspiremovecentraldays[.]net — hosted on actor IPs (128.199.6.246, 161.35.123.176, 185.170.215.170 and others). It also stood up free webmail accounts under the persona john.macperson / john.macperson2021 (yandex.com, yahoo.com, gmail.com, protonmail.com) used as the SUGARDUMP SMTP exfil sender/recipient mailboxes.
- **Why a hunt, not a rule:** Domain registration and account creation happen entirely on the adversary's side — there is no victim event to alert on, so this cannot be a detection rule at all. The listed domains and mailboxes are Summiting Level 1 IOCs that the actor rotates cheaply; matching them is a pivot, not a durable hunt. The hunt's value is *proactive discovery*: using the known estate's infrastructure fingerprints (shared registrar, nameservers, hosting ASN, TLS cert issuer, registration cadence, the "-ish brand" naming and punycode pattern) to surface the *next* batch of domains before they are weaponized — and the "john.macperson"-style persona pattern to catch reuse — then corroborating against our mail and egress telemetry. That external-to-internal fusion and judgement is analyst work, not an alert condition.
- **Data-based note:** run this partly in a data-based mode against your NRD/passive-DNS feed — enumerate new registrations that resemble your brand/partners with no prior attack tip, and let the infrastructure-fingerprint overlap with the known UNC3890 estate surface candidates.

## Data sources required

- Passive DNS + newly-registered-domain (NRD) feed, WHOIS/RDAP, and TLS certificate transparency logs (Censys/crt.sh) — external infrastructure discovery
- Domain-registration/hosting metadata (registrar, nameservers, hosting ASN, cert issuer) to fingerprint against the known UNC3890 IPs (128.199.6.246, 161.35.123.176, 185.170.215.170, 143.110.155.195, 144.202.123.248)
- Inbound + outbound email gateway logs (sender/recipient address, sending IP) — for the john.macperson personas
- Web proxy / DNS resolver logs — for any internal resolution of surfaced lookalike domains
- Brand-monitoring service scoped to your own org and key maritime/sector partners

## Query starting point

Platform: `Splunk SPL` — surface inbound/outbound touches of the actor personas and freshly-resolved brand lookalikes

```spl
(index=email (sender_address="john.macperson*" OR recipient_address="john.macperson*"
              OR sender_domain IN ("yandex.com","protonmail.com" ) sender_local="john.macperson*"))
OR
(index=proxy OR index=dns
   dest_domain IN ("lirikedin.com","xn--lirkedin-vkb.com","rnfacebook.com","office365update.live",
                   "pfizerpoll.com","celebritylife.news","fileupload.shop","naturaldolls.store",
                   "xxx-doll.com","aspiremovecentraldays.net"))
| eval signal=case(index=="email","actor-persona-in-mailflow","actor-domain-resolved")
| stats earliest(_time) as first_seen latest(_time) as last_seen
        values(signal) as signals values(user) as users values(src_ip) as src by index, sourcetype
| convert ctime(first_seen) ctime(last_seen)

``` 
Pair with an external sweep (outside Splunk): query passive-DNS/CT for domains registered in the last 90 days that (a) contain your brand or a partner-shipping-brand token with a homoglyph/"rn"/punycode twist AND (b) resolve into, or share a nameserver/cert-issuer with, the known UNC3890 hosting IPs.

## Triage guidance

- **Likely malicious:** an inbound email from a john.macperson* mailbox, or ANY outbound SMTP from a workstation toward those mailboxes (that is SUGARDUMP exfil — pivot immediately to the detection pack T1048); a freshly-registered domain twisting *your* brand or a partner-shipping brand that shares a nameserver, hosting ASN or TLS cert issuer with the known UNC3890 estate; a punycode/homoglyph brand domain resolved by an internal user. Infrastructure-fingerprint overlap with the known estate is the load-bearing corroborator.
- **Likely benign / expected:** legitimate brand-protection registrations your own org or a partner made defensively; common webmail traffic to yandex/yahoo/gmail/protonmail that is *not* the john.macperson persona (these providers are legitimate — key on the exact mailbox, never the provider domain); NRD false positives where a lookalike is an unrelated business with no infrastructure tie to the actor. A brand-lookalike registration with no estate overlap and no internal touch is intel to watch, not a finding.
- **Pivot next:** an outbound SMTP to a john.macperson mailbox is a confirmed exfil — escalate to incident-response-coordinator and pivot to the detection pack (T1048 / T1041 / T1555.003) on the sending host. A newly-surfaced actor-fingerprinted lookalike of your brand should be pre-emptively blocked at the proxy/mail gateway, fed to HUNT-02 as a new capture domain, and reported to hand-off to detection-engineering if it warrants a standing lookalike-domain analytic. Notify any impersonated partner.

## References

- https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping
- https://thehackernews.com/2022/08/suspected-iranian-hackers-targeted.html
- https://attack.mitre.org/techniques/T1583/001/
- https://attack.mitre.org/techniques/T1585/002/
