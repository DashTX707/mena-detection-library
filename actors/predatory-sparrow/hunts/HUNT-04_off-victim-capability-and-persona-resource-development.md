# Hunt: Predatory Sparrow — off-victim capability development & persona/social-account resource-development

- **Hypothesis:** This actor's preparation happens *off* the victim: a purpose-built, reusable wiper assessed to have been in development for ~3 years (T1587.001), and a public "Gonjeshke Darande / Predatory Sparrow" Telegram-and-social persona (T1585.001) used to claim operations, publish "proof" CCTV, and leak exfiltrated data. Neither is endpoint-observable in a defender's estate — so this hunt is deliberately **intel/OSINT-driven** and its findings are attribution and early-warning, not host alerts. The falsifiable proposition for a defender: *if* this actor (or the Meteor/Stardust/Comet family) is being retooled or is spinning up persona infrastructure against our region/sector, *then* we can observe it in two places — (1) **malware-repository / sandbox telemetry** showing new samples that share the Meteor family's configurable structure, `ms*`/`env`/`nti` naming, `hackemall` RAR password, `abcdz` XOR key, or `msconf.conf`-style encrypted config; and (2) **social/OSINT monitoring** showing new or reactivated actor-branded Telegram/X channels, look-alike personas, or pre-leak "teaser" posts naming our sector. A single new sample or new channel is weak; a **new Meteor-family sample AND a freshly-provisioned actor channel referencing our region in the same window** is a meaningful pre-operational indicator.
- **ATT&CK:**
  - T1587.001 — Develop Capabilities: Malware (resource-development) — Meteor is an externally-configurable, ~3-years-in-development, reusable destructive tool (custom + open-source, heavy sanity-checking) with Stardust/Comet variants; hunt malware-repo/sandbox space for family reuse and retooling.
  - T1585.001 — Establish Accounts: Social Media Accounts (resource-development) — the actor operates public Telegram/social channels to claim ops, publish CCTV "proof", and run hack-and-leak; hunt OSINT/brand-monitoring for new or reactivated actor-controlled channels.

- **Actor procedure:** SentinelLabs assesses Meteor as a purpose-built, externally-configurable wiper (config-driven `paths_to_wipe` / `processes_to_kill`, encrypted `msconf.conf`, XOR `abcdz`) built for **reuse beyond a single operation**, consistent with the related Stardust and Comet variants and a multi-year development effort — i.e., the toolchain is a maintained capability, not a one-off. On the persona side, the actor runs a public **Gonjeshke Darande / Predatory Sparrow Telegram presence** (plus other social channels) as the delivery mechanism for its messaging strategy: it *pre-announces and post-claims* operations, releases CCTV footage as "proof" of OT impact (the steel-plant molten-metal spill), and publishes exfiltrated documents/emails. The social channel is operational infrastructure — provisioning or reactivating it is a leading indicator of an imminent hack-and-leak.

- **Why a hunt, not a rule:** Both techniques occur entirely on infrastructure the defender does not own and cannot instrument — there is no endpoint event to alert on, so a detection rule is structurally impossible here. The work is **retro-hunting malware repositories/sandboxes** (VirusTotal, MalwareBazaar, internal detonation) for family-shared implementation traits, and **OSINT/brand-monitoring** for persona activity, then correlating either against our region/sector exposure. That is analytic, judgement-heavy intel hunting. If a family-shared, hard-to-change implementation trait proves robust (e.g., the `msconf.conf` encrypted-config structure or a distinctive code construct — a Summiting Level-4/5 implementation-core observable rather than a swappable hash), package it as a YARA hunting rule and, if it holds, hand a file/EDR analytic to detection-engineering; do not alert on "the actor developed malware."

## Data sources required

- Malware-repository / sandbox retro-hunt: VirusTotal Intelligence / Hunting, MalwareBazaar, internal sandbox detonation output — searchable on strings, imports, config structure, and YARA
- OSINT / brand & persona monitoring: Telegram channel monitoring, X/other social, dark-web and paste-site feeds keyed to the "Gonjeshke Darande / Predatory Sparrow" persona and to our brand/region/sector
- Threat-intel platform / MISP for family tracking (Meteor / Stardust / Comet / Indra cluster) and for logging new samples and channels as intel, not as detections
- Regional/sector exposure list (which of our assets/brands would be a plausible target) to make "references our sector" a meaningful correlator

## Query starting point

Platform: `YARA (repository / sandbox retro-hunt)` — surface Meteor-family capability reuse on implementation-core traits (robust), not on the reported hashes (swappable)

```yara
rule PredatorySparrow_Meteor_family_capability_hunt
{
    meta:
        author = "MENA Detection Library — threat-hunter"
        description = "HUNT-ONLY: Meteor/Stardust/Comet family reuse — config structure, actor strings, packaging"
        note = "For malware-repo/sandbox hunting and attribution, NOT production endpoint detection"
        reference = "https://www.sentinelone.com/labs/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/"
    strings:
        $cfg1  = "msconf.conf" ascii wide
        $cfg2  = "paths_to_wipe" ascii wide
        $cfg3  = "processes_to_kill" ascii wide
        $rarpw = "hackemall" ascii wide
        $xor   = "abcdz" ascii wide
        $lock  = "__lock6423900.dat" ascii wide
        $n1    = "mssetup.exe" ascii wide
        $n2    = "msapp.exe" ascii wide
        $n3    = "nti.exe" ascii wide
        $bat   = "envxp.bat" ascii wide
    condition:
        // config-structure OR packaging trait, backed by a second family artifact — reduces coincidental hits
        (2 of ($cfg*)) or ($rarpw and $xor) or ($lock) or (2 of ($n1,$n2,$n3,$bat))
}
```

Companion OSINT method (no query engine): stand up monitoring for new/reactivated "Gonjeshke Darande / Predatory Sparrow" Telegram and social channels and pre-leak teaser posts; alert the intel team when a new channel or a "proof"/"we will release" post references our region or sector, and correlate its timing against any new Meteor-family sample surfaced by the YARA hunt above.

## Triage guidance

- **Likely malicious / high-value intel:** a newly-uploaded sample matching the family config structure (`msconf.conf` + `paths_to_wipe`/`processes_to_kill`) or the `hackemall`+`abcdz` packaging, especially if first-seen geo/submitter ties to the region and it post-dates known operations (retooling); a **newly provisioned or reactivated** actor-branded Telegram channel, or a "proof"/pre-leak teaser naming our sector — treat the *conjunction* of a fresh sample and fresh persona activity in one window as a pre-operational warning.
- **Likely benign / expected:** security-researcher re-uploads and reference samples of the *known* Meteor toolchain (expected, not new capability — dedupe against known hashes); fan/parody or reporting accounts re-sharing the persona's content (not actor-controlled); brand-monitoring hits on look-alike names unrelated to this actor. A repo hit on the exact known hashes is history; a *novel* sample sharing implementation-core traits is the signal.
- **Pivot next:** a novel family sample is attribution + YARA-signature material — extract robust implementation-core traits, push the hunting YARA to sandbox/EDR retro-hunt, and if a trait proves durable, hand a scoped file analytic to detection-engineering. Persona/channel activity referencing our sector is early warning for an imminent hack-and-leak — brief the intel/leak-monitoring function (feeds HUNT-05) and raise regional-CNI/OT readiness. This lane's output is intel and pre-warning; route confirmed capability/persona findings to cti-expert and incident-response-coordinator, not to an alert rule.

## References

- https://www.sentinelone.com/labs/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/
- https://en.wikipedia.org/wiki/Predatory_Sparrow
- https://attack.mitre.org/techniques/T1587/001/
- https://attack.mitre.org/techniques/T1585/001/
