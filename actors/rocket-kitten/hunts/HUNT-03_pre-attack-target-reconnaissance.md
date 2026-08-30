# Hunt: Rocket Kitten — pre-attack victim and org profiling (targeted-exposure hunt)

- **Hypothesis:** If Rocket Kitten is preparing to target us, then before any lure is sent our *specific* people and org details are being profiled off-victim — the recovered operational database held ~1,600 individually profiled targets. We cannot see the actor's OSINT directly, but we *can* invert the hunt: enumerate which of our staff match the actor's targeting profile (academics, scientists, journalists, human-rights liaisons, ministry/defense/policy experts on MENA topics), then check our external-exposure surface (public bios, harvested-email breach corpora, brand/persona-monitoring, referer spikes to public staff pages) for the reconnaissance and enumeration footprint that precedes their spear-phish. The finding is a targeted-user whose external exposure is *both* high and *newly probed*, weighted by fit to the actor's known victimology.
- **ATT&CK:**
  - T1589 — Gather Victim Identity Information (reconnaissance) — profiling names, roles, emails, phone numbers and interests of individual targets to craft tailored lures.
  - T1591 — Gather Victim Org Information (reconnaissance) — identifying and prioritizing organizations of Iranian state interest (defense, academia, ministries, research institutes, media, NGOs).

- **Actor procedure:** Per Check Point's *9 Lives* and ClearSky's *Thamar Reservoir*, Rocket Kitten runs research-heavy, persona-driven operations. Their exposed target-management database revealed ~1,600 profiled individuals — scholars, scientists, CEOs, ministry officials, education institutes, media/journalists and human-rights activists across the Middle East, Europe and the US — each researched enough to support highly tailored spear-phishing and fake identities (correct language, role, professional interests). Org-level prioritization focuses on Israeli defense and academic institutions, ministries, research institutes, media outlets and human-rights NGOs of clear Iranian state interest. This is patient, low-tech reconnaissance, not intrusion.

- **Why a hunt, not a rule:** The reconnaissance itself is entirely off-victim — OSINT, database-building, phone/email profiling on the actor's side — with essentially zero enterprise telemetry to alert on. This hunt is deliberately a *data-based/attack-informed exposure assessment*, not an alert: it fuses HR/role data, public-footprint enumeration and external monitoring into a prioritized watchlist of who the actor is most likely to pursue, which then *feeds the weighting of every other hunt in this pack* (HUNT-01/02). There is no rule to hand off; the deliverable is a maintained targeted-user list and a visibility-gap statement, refreshed on a recurring cadence and after any relevant geopolitical trigger.

## Data sources required

- HR / directory data (roles, departments, research topics, public-facing staff) to match against Rocket Kitten victimology.
- External attack-surface / exposure monitoring — public staff bios and contact details, credential-breach corpora containing corporate addresses, paste sites.
- Public web-server / CDN referer and access logs for staff-profile and research-directory pages — enumeration or scraping spikes.
- Brand-, persona- and domain-monitoring intel feeds (shared with HUNT-04) for early signs our people/org are being staged against.

## Query starting point

Platform: `KQL / Microsoft Sentinel` — build the prioritized targeted-user watchlist and surface abnormal external enumeration of their public pages.

```kusto
// (a) Match staff to Rocket Kitten victimology → prioritized watchlist seed
let targetedRoles = dynamic(["professor","researcher","scientist","scholar","fellow",
    "journalist","reporter","editor","human rights","policy","analyst","ministry",
    "defense","nuclear","missile","middle east","iran"]);
let candidates =
    IdentityInfo
    | where JobTitle has_any (targetedRoles) or Department has_any (targetedRoles)
    | project AccountUpn, JobTitle, Department, City, Country;
// (b) Abnormal external enumeration of public staff/research pages (scraping / recon)
let recon =
    W3CIISLog                                   // or CDN/proxy access logs for public site
    | where TimeGenerated > ago(30d)
    | where csUriStem has_any ("/staff","/people","/faculty","/directory","/research","/profile")
    | summarize hits = count(), pages = dcount(csUriStem),
               uas = dcount(csUserAgent), first = min(TimeGenerated), last = max(TimeGenerated)
             by cIP
    | where hits > 200 or pages > 50            // enumeration-like breadth from one source
    | order by hits desc;
candidates
| project AccountUpn, JobTitle, Department, Country      // deliverable: prioritized watchlist
| order by Department asc
```

## Triage guidance

- **Likely malicious (worth escalating to intel/awareness):** a scraping source enumerating the full staff/research directory from a MENA-nexus ASN or hosting provider, timed with brand/persona-monitoring hits naming our org; targeted staff whose corporate emails newly appear in breach/paste corpora together with role-accurate profiling; a spike in look-alike domain registrations echoing our institution's name (hand to HUNT-04).
- **Likely benign / expected:** search-engine and academic-index crawlers legitimately enumerate public faculty/research pages — baseline known good bots by UA and ASN; journalists' and collaborators' normal browsing of staff pages; routine breach-corpus presence of long-lived corporate emails is background, not a fresh signal. High exposure alone is not a finding; *newly probed* high exposure on a victimology-matched user is.
- **Pivot next:** publish/refresh the prioritized targeted-user watchlist consumed by HUNT-01 and HUNT-02; brief the highest-fit users on persona/impersonation lures and enable stronger auth (phishing-resistant MFA); feed any look-alike-domain or persona hits into HUNT-04; document the reconnaissance visibility gap (most of it is unobservable) so leadership understands detection begins at delivery, not recon.

## References

- https://blog.checkpoint.com/research/rocket-kitten-a-campaign-with-9-lives/
- https://www.clearskysec.com/thamar-reservoir/
- https://attack.mitre.org/techniques/T1589/
- https://attack.mitre.org/techniques/T1591/
