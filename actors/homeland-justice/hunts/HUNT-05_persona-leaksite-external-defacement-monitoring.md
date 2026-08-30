# Hunt: Homeland Justice persona & external leak/defacement monitoring (off-victim early breach disclosure)

- **Hypothesis:** Because Homeland Justice / Karma runs its impact off-victim — establishing Telegram channels and leak websites to claim intrusions, message victims, and publish stolen data — the earliest external evidence of a breach may appear *outside* host/network telemetry: our (or a peer's) organizational data, credentials, screenshots, or a named claim surfacing on a Homeland Justice/Karma persona channel or leak site. This is a data-based external-monitoring hunt: watch the actor's known publication surfaces and brand/data mentions for a never-before-seen disclosure that references us, treating a matching leak as confirmation of compromise that internal logs may not yet show.
- **ATT&CK:**
  - T1585.001 — Establish Accounts: Social Media Accounts (resource development) — hunt the persona's outputs, not its creation
  - T1491.002 — Defacement: External Defacement (impact) — external leak/messaging as the observable

- **Actor procedure:** Per AA22-264A and Check Point, the actor operates the public "Homeland Justice" persona (Telegram channel + leak website) — and the analogous "Karma" brand in Void Manticore's Israel operations — to claim responsibility, publish stolen government/organizational data in staged releases, and deliver political/psychological messaging after the destructive stage. The persona and its posts are established and hosted entirely off-victim; the leak *is* the external defacement.
- **Why a hunt, not a rule:** Off-victim persona and leak activity is LOW detection-feasibility because none of it touches defender host or network logs — there is nothing internal to alert on, so this can only ever be an external-monitoring hunt, not a SIEM rule. Even externally, an automated keyword alert on "Homeland Justice" would drown in news/threat-intel reporting about the actor rather than an actual *fresh disclosure of our data*. The discriminating judgement is distinguishing a genuine new leak that references our org/data (never-before-seen disclosure) from commentary, re-posts, and coverage — which requires analyst reasoning over the persona's channels and data-mention feeds. **Edge case — visibility gap:** if we have no external/brand/leak-site monitoring capability at all, that absence is itself the finding: document it as a coverage gap, because "we would learn of our own breach only from the attacker's Telegram" is an actionable deficiency.
- **This is a hunt, not an internal alert, and it is not detection-engineering's to rule-ify** — a confirmed matching leak is escalated as an incident, and the standing monitoring is an intel/brand-protection function, not a host detection.

## Data sources required

- Threat-intel / brand-protection monitoring of the Homeland Justice & Karma Telegram channels and known leak-site URLs/mirrors (Tor + clearnet)
- Leak-aggregation / paste / credential-dump feeds and dark-web monitoring keyed to org names, domains, VIP identities, and data fingerprints
- Internal data fingerprints / canary documents to match published samples against owned data
- (If none of the above exist) an inventory of external-monitoring coverage — to record the gap

## Query starting point

Platform: `Threat-intel / brand-monitoring platform (external) + KQL for correlation` — new leak/claim referencing owned data, corroborated internally

```kusto
// External-monitoring hits are ingested as a custom table (LeakMonitor_CL) from the TI/brand feed.
// Surface *new* disclosures that reference our org and are not mere news/reporting.
LeakMonitor_CL
| where TimeGenerated > ago(7d)
| where SourceChannel_s has_any ("HomelandJustice","Homeland Justice","Karma","Void Manticore")
      or SourceType_s in ("telegram","leaksite","paste","credential-dump")
| where MatchedSelector_s has_any (dynamic(["<our-domains>","<org-name>","<VIP-handles>"]))
| where PostType_s != "news-coverage"                        // exclude reporting about the actor
| extend firstSeen = TimeGenerated
| summarize earliest = min(firstSeen), samples = make_set(PostUrl_s, 10),
            selectors = make_set(MatchedSelector_s, 20) by SourceChannel_s, PostTitle_s
| order by earliest desc
// Corroboration pivot: for any hit, match published sample hashes/canary tokens against owned data,
//   and cross-check the disclosure window against HUNT-04 (exfil) and HUNT-01 (destruction) timelines.
```

## Triage guidance

- **Likely malicious / true positive:** a fresh Homeland Justice/Karma post that publishes data, credentials, or screenshots verifiably matching our owned assets (canary token, document fingerprint, real internal path/hostnames), or names our organization as a victim ahead of any internal detection; staged/incremental releases consistent with the actor's leak cadence. For peers in government or Israel-linked sectors, a new named victim is early warning to hunt our own environment for the same chain.
- **Likely benign / not a fresh breach:** security-vendor and press reporting *about* Homeland Justice, historical re-posts of the 2022 Albania dumps, recycled/aggregated credential lists not traceable to us, and impersonator channels re-sharing old data — corroborate every match against owned-data fingerprints before believing it. An unverifiable claim with no matching sample is inconclusive, not confirmed.
- **Pivot next:** a corroborated fresh leak of our data = confirmed compromise regardless of internal log state → **escalate to incident-response-coordinator immediately** and drive internal hunting backward from the disclosure (HUNT-04 exfil chain, HUNT-03 re-entry, HUNT-01 destruction precursors) to find and contain the intrusion before the destructive stage fires. If external monitoring does not exist, escalate the visibility gap to close it as its own action.

## References

- https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a
- https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/
- https://attack.mitre.org/techniques/T1585/001/
- https://attack.mitre.org/techniques/T1491/002/
