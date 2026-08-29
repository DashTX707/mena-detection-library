# Gaza Cybergang / Molerats (G0021) — Detection & Hunt Pack

> **Attribution:** Palestinian-nexus, politically motivated — **high confidence**
> **MENA targeting:** Palestinian Territories, Jordan, Israel, Lebanon, Egypt
> **Sectors:** Diplomatic, government, NGOs, media, banking, healthcare
> **Aliases:** Molerats, Operation Molerats, TA402, "Group1" / SneakyPastes cluster

## Summary

Gaza Cybergang (a.k.a. Molerats) is a Palestinian-nexus, politically-motivated espionage actor active across the Levant and North Africa. Its tradecraft is characterized by **spear-phishing with politically-themed lures**, **commodity and custom .NET backdoors** (Spark, Pierogi, DropBook, SharpStage, MoleNet, IronWind), **abuse of legitimate cloud services** (Dropbox, Google Drive, Facebook, cloud pastebins) for C2 and exfiltration, and living-off-the-land staging. The reliance on cloud-service C2 and document-lure delivery is why this pack splits between endpoint/document **Sigma detections** and **hunts** for the cloud-C2 and infrastructure behavior that needs proxy/network context.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Operation SneakyPastes | Jan 2018 – Jan 2019 | 240+ victims across 39 countries; paste-site staging | [Securelist – SneakyPastes](https://securelist.com/gaza-cybergang-group1-operation-sneakypastes/90068/) |
| NimbleMamba (TA402) | Nov 2021 – Jan 2022 | Middle East government targeting | Proofpoint (verify dedicated citation) |
| IronWind (TA402) | Jul – Oct 2023 | Complex infection chains vs. ME governments | [Proofpoint – TA402 IronWind](https://www.proofpoint.com/us/blog/threat-insight/ta402-uses-complex-ironwind-infection-chains-target-middle-east-based-government) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**36 techniques**, enriched from a 16-technique tracker seed via MITRE G0021 + reporting)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **17 Sigma rules** covering 19 detection-lane techniques, all validated clean (0 issues)
- [`hunts/`](hunts/) — **7 consolidated hunt hypotheses** covering the 17 hunt-lane techniques (cloud-service-C2 flagship)
- [`iocs/`](iocs/) — publicly-sourced indicators (currently empty; Gaza Cybergang IOCs live in vendor reports — Securelist SneakyPastes, Proofpoint IronWind — not yet ingested)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **36** across 9 tactics
- Lane split: **19 detection / 17 hunt** (see `intel/routing.json`)
- Detections: **17 Sigma files** · Hunts: **7** · IOCs: **0** (backfill pending)

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from MITRE G0021 + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** the tracker seed held only 16 techniques; cti-expert enriched to 36 from MITRE G0021 and Proofpoint/Cybereason/Securelist reporting (per-technique sources in `cti-pipeline.json`). `routing.json` is authored by the read-only decision-agent and persisted by the orchestrator. IOCs are not yet backfilled — the signature cloud-service C2 tradecraft means few atomic network IOCs; sample hashes from the vendor reports can be added on request.
