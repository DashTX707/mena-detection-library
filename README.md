# MENA Detection Library

**Deployable, citation-backed detection & hunt content for threat actors that target the Middle East and North Africa.**

Most public detection collections (SigmaHQ, Elastic detection-rules) are excellent but region-agnostic. Defenders in MENA face a specific adversary mix — Iran-nexus espionage (MuddyWater, OilRig, Charming Kitten), Palestinian-nexus groups (Gaza Cybergang, WIRTE, Arid Viper), regional wiper operators (Agrius, Void/Scarred Manticore), and an active ransomware ecosystem — and nobody maintains ready-to-deploy detection content organized around *those* actors.

This project fills that gap. For each tracked actor you get a **pack**: Sigma detections, threat-hunt hypotheses, an ATT&CK technique map, a Navigator layer, and (where responsibly sourced) IOCs — every item traceable to a public source.

> **Companion to** the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker), which answers *"who targets this region."* This repo answers *"and how do I detect and hunt them."*

## How content is produced

Packs are generated and maintained by a transparent, four-stage analyst pipeline — the same one a human CTI/detection team would run, applied consistently:

```
source reporting
      │
      ▼
  cti-expert          Stage 1  extract TTPs, IOCs, procedures, confidence
      │
      ▼
  decision-agent      Stage 2  route each TTP: detectable rule  vs.  hunt hypothesis
      │
      ├──────────────► detection-engineer   Stage 3a  author + validate Sigma
      │
      └──────────────► threat-hunter        Stage 3b  write hunt hypotheses + queries
```

Every pack records its provenance so you can audit how a rule was derived.

## Repository layout

```
actors/<actor>/
  README.md              actor overview: attribution, targeting, campaigns, sources
  ttps.md                full ATT&CK technique mapping
  navigator-layer.json   ATT&CK Navigator heatmap
  intel/                 Stage-1/2 pipeline artifacts (cti-pipeline.json, routing.json)
  detections/            Sigma rules (.yml) — validated where a validator is available
  hunts/                 hunt hypotheses (.md) with platform queries
  iocs/                  publicly-sourced indicators (iocs.csv)
templates/               skeleton for contributing a new actor pack
scripts/                 helpers (validation, Navigator export)
```

## Using the detections

- **Sigma → your SIEM:** convert with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) / pySigma backends (Splunk, Sentinel/KQL, Elastic, etc.), e.g. `sigma convert -t splunk actors/muddywater/detections/`.
- **Hunts:** each hunt states a hypothesis, the data sources needed, a platform-specific query starting point, and what a true/false positive looks like.
- **Every rule is a starting point, not a turnkey guarantee.** Tune to your telemetry and baseline. Read the `falsepositives` and validation notes on each rule.

## Coverage

| Actor | Attribution | Status | TTPs | Detections | Hunts |
|---|---|---|---|---|---|
| [MuddyWater (G0069)](actors/muddywater/) | Iran-nexus (MOIS) | ✅ published | 68 | 32 | 14 |
| [OilRig / APT34 (G0049)](actors/oilrig/) | Iran-nexus (MOIS) | ✅ published | 87 | 29 | 12 |
| [Gaza Cybergang / Molerats (G0021)](actors/gaza-cybergang/) | Palestinian-nexus | ✅ published | 36 | 17 | 7 |
| [Agrius (G1030)](actors/agrius/) | Iran-nexus · destructive | ✅ published | 34 | 18 | 6 |
| [WIRTE (G0090)](actors/wirte/) | Palestinian-nexus · +wiper | ✅ published | 39 | 13 | 9 |
| [Scarred Manticore (Storm-0861)](actors/scarred-manticore/) | Iran-nexus · LIONTAIL | ✅ published | 28 | 10 | 7 |
| [Charming Kitten (APT35, G0059)](actors/charming-kitten/) | Iran-nexus · IRGC | ✅ published | 84 | 26 | 8 |
| [APT33 (G0064)](actors/apt33/) | Iran-nexus · aviation/Shamoon | ✅ published | 48 | 26 | 6 |
| [Void Manticore (Storm-1084)](actors/void-manticore/) | Iran-nexus · BiBi wiper | ✅ published | 21 | 10 | 5 |
| [HEXANE / Lyceum (G1001)](actors/hexane/) | Iran-nexus · telecom/energy | ✅ published | 63 | 22 | 8 |
| [APT39 / Chafer (G0087)](actors/apt39/) | Iran-nexus (MOIS) · surveillance | ✅ published | 53 | 26 | 6 |
| [CyberAv3ngers (IRGC-CEC)](actors/cyberav3ngers/) | Iran-nexus · OT/ICS | ✅ published | 20 | 10 | 5 |
| [Moses Staff (Cobalt Sapling)](actors/moses-staff/) | Iran-nexus · hack-and-leak | ✅ published | 28 | 13 | 6 |
| [Tortoiseshell (G0139)](actors/tortoiseshell/) | Iran-nexus (IRGC) · supply-chain | ✅ published | 74 | 28 | 7 |
| [UNC1860](actors/unc1860/) | Iran-nexus (MOIS) · access broker | ✅ published | 30 | 9 | 6 |
| [Cotton Sandstorm (G1009)](actors/cotton-sandstorm/) | Iran-nexus (IRGC) · influence | ✅ published | 30 | 9 | 7 |
| [Homeland Justice (Storm-0842)](actors/homeland-justice/) | Iran-nexus · Albania wiper | ✅ published | 34 | 14 | 5 |
| [Pioneer Kitten (Fox Kitten)](actors/pioneer-kitten/) | Iran-nexus · access broker | ✅ published | 50 | 26 | 5 |
| [POLONIUM (Plaid Rain)](actors/polonium/) | Lebanon-nexus · MOIS-linked | ✅ published | 42 | 17 | 6 |
| [Arid Viper (APT-C-23)](actors/arid-viper/) | Palestinian-nexus · spyware | ✅ published | 40 | 15 | 6 |
| [Predatory Sparrow (Gonjeshke Darande)](actors/predatory-sparrow/) | Israel-linked · OT wiper | ✅ published | 34 | 23 | 6 |
| [Imperial Kitten (CURIUM)](actors/imperial-kitten/) | Iran-nexus · IRGC | ✅ published | 35 | 19 | 5 |
| [UNC1549 (TA455)](actors/unc1549/) | Iran-nexus · aerospace/defense | ✅ published | 40 | 28 | 5 |
| [UNC3890](actors/unc3890/) | Iran-nexus · shipping/energy | ✅ published | 32 | 15 | 5 |
| [Ballistic Bobcat (APT35-adjacent)](actors/ballistic-bobcat/) | Iran-nexus · Sponsor backdoor | ✅ published | 31 | 15 | 3 |
| [Greenbug (ISMDOOR)](actors/greenbug/) | Iran-nexus · Shamoon precursor | ✅ published | 35 | 17 | 2 |
| [Sea Turtle (Marbled Dust)](actors/sea-turtle/) | Türkiye-nexus · DNS hijack | ✅ published | 33 | 15 | 5 |
| [Bahamut (Windshift-adjacent)](actors/bahamut/) | Mercenary · hack-for-hire | ✅ published | 41 | 6 | 7 |

**28 actors · 1190 ATT&CK techniques · 508 Sigma detections · 179 hunt packages · 974 sourced IOCs.**

_More actors to follow. See [CONTRIBUTING.md](CONTRIBUTING.md) to add one._

## Scope, sourcing & disclaimer

- Detection content is derived from **publicly available** threat reporting; each pack cites its sources.
- This repository contains **no** stolen data, credentials, live malware, or PII — only defensive detection logic and pointers to public reporting.
- Detection logic reflects public reporting at time of writing; adversary tradecraft evolves. Verify time-sensitive detail against primary sources before operational reliance.
- For **defensive use only.**

## License

Detection content (Sigma rules, hunts) is released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) where applicable; documentation under CC BY 4.0. See [LICENSE.md](LICENSE.md).
