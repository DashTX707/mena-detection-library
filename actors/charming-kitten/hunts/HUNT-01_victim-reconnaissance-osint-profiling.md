# Hunt: Charming Kitten victim reconnaissance & OSINT identity profiling

- **Hypothesis:** If Charming Kitten (APT35/APT42) is preparing an operation against our people, then in the weeks before any lure lands we should observe off-victim reconnaissance footprints — our named executives/journalists/researchers appearing in newly-created persona contact attempts, tracking-pixel callbacks from mail-render events resolving to actor infrastructure, and inbound "profiling" emails (blank/benign first-contact) whose embedded beacons harvest recipient IP/host-software before any credential ask.
- **ATT&CK:**
  - T1589 — Gather Victim Identity Information (reconnaissance)
  - T1589.001 — Gather Victim Identity Information: Credentials (reconnaissance)
  - T1589.002 — Gather Victim Identity Information: Email Addresses (reconnaissance)
  - T1591.001 — Gather Victim Org Information: Determine Physical Locations (reconnaissance)
  - T1590.005 — Gather Victim Network Information: IP Addresses (reconnaissance)
  - T1592.002 — Gather Victim Host Information: Software (reconnaissance)

- **Actor procedure:** APT42/TA453 profiles targets' identities — names, roles, affiliations, relationships, physical locations and email addresses — to build convincing personas and pick spoofed institutions/individuals for lures (Harvard T.H. Chan School, "Daniel Serwer", "David Webb", "Jamileh Nedai"). Credential collection is the strategic objective; it is seeded here. Recon email carries tracking pixels/web beacons that profile recipient IP addresses and, indirectly, host software, to tailor payload delivery (e.g. TAMECAT branches on Windows Defender presence). Targets are journalists, activists, academics, NGO/government personnel in Israel, the Gulf, Iran's diaspora, US/UK/Europe.
- **Why a hunt, not a rule:** Almost all of this happens off-victim, against public sources and third-party platforms — there is no enterprise log that fires. The value is threat-intel awareness plus a small observable sliver (beacon callbacks at mail-render, benign-looking first-contact email). Base rates for "email with a remote image" and "someone googled our CEO" are astronomically high; this can never be a reliable alert. It is a periodic, intel-driven sweep that flags *which named individuals* are being circled so the SOC can pre-brief them and watch their accounts more closely.

## Data sources required

- Threat-intel / brand-monitoring feeds (persona sightings, credential-dump mentions of corporate emails)
- Secure email gateway (SEG) logs: remote-image/tracking-pixel loads, first-contact senders, HTML beacon URLs
- Have-I-Been-Pwned / breach-corpus monitoring for corporate and personal (high-risk-role) email addresses
- Web proxy / DNS at the mail-render stage (image beacon callbacks)
- HR/exec-protection list of high-risk roles (journalists, dissidents, policy staff, legal/NGO leadership)

## Query starting point

Platform: `Splunk SPL` (SEG + proxy) — surface benign first-contact email to high-risk roles that loads a remote beacon from young/rare infrastructure

```
index=email sourcetype=seg
| eval recipient=lower(recipient)
| lookup highrisk_roles.csv email AS recipient OUTPUT role
| where isnotnull(role)
| search attachment_count=0 url_count<=1 (has_remote_image=1 OR body_beacon=1)
| stats count min(_time) AS first_seen values(beacon_domain) AS beacon_domains
        values(sender) AS senders by recipient role
| lookup nrd_feed.csv domain AS beacon_domains OUTPUT domain_age_days
| where domain_age_days<90 OR isnull(domain_age_days)
| sort - count
```

Companion (intel-side, not a SIEM query): monitor breach/paste feeds and persona trackers for any corporate domain email or named high-risk individual; correlate new hits against the recon email timeline above.

## Triage guidance

- **Likely malicious:** benign "just reaching out"/"can I interview you" first-contact email to a journalist/policy/legal/NGO high-risk role, no payload yet, that silently loads a beacon from a <90-day domain; the same named individuals then surfacing in persona contact on LinkedIn/X; corporate emails appearing in a fresh credential dump shortly before targeted lures.
- **Likely benign / expected:** marketing/newsletter tracking pixels from established ESPs (Mailchimp, SendGrid) on aged domains; legitimate press/research outreach from verifiable outlets; recruiter contact matching a real company. Baseline your top ESP beacon domains and suppress.
- **Pivot next:** for a flagged individual, pivot to HUNT-02 (is a persona already engaging them?) and HUNT-03 (does the beacon/sender domain cluster with known CK lookalike infrastructure?). Pre-brief the target, force a credential reset, and raise monitoring on their account (see detection pack: impossible-travel, MFA-fatigue, app-password).

## References

- https://cloud.google.com/blog/topics/threat-intelligence/untangling-iran-apt42-operations
- https://attack.mitre.org/groups/G0059
