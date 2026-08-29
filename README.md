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

_More actors to follow. See [CONTRIBUTING.md](CONTRIBUTING.md) to add one._

## Scope, sourcing & disclaimer

- Detection content is derived from **publicly available** threat reporting; each pack cites its sources.
- This repository contains **no** stolen data, credentials, live malware, or PII — only defensive detection logic and pointers to public reporting.
- Detection logic reflects public reporting at time of writing; adversary tradecraft evolves. Verify time-sensitive detail against primary sources before operational reliance.
- For **defensive use only.**

## License

Detection content (Sigma rules, hunts) is released under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) where applicable; documentation under CC BY 4.0. See [LICENSE.md](LICENSE.md).
