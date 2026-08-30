# POLONIUM — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Lebanon (one intergovernmental organization with a presence in Lebanon)  
> **Sectors:** Critical manufacturing, Information technology, Defense industrial base / defense industry, Engineering, Law / legal, Communications / media  
> **Aliases:** POLONIUM, Plaid Rain, MITRE ATT&CK G1005

## Summary

Lebanon-based cyberespionage group. Microsoft assesses with MODERATE confidence that POLONIUM coordinates its operations with multiple actors affiliated with Iran's Ministry of Intelligence and Security (MOIS), based on victim overlap, common techniques and shared tooling (notably OneDrive-based C2 and the AirVPN service used by MOIS-affiliated groups such as MERCURY/MuddyWater). ESET independently corroborates the Lebanon-based, MOIS-linked assessment.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Israeli-organization espionage campaign (Microsoft disclosure) | February 2022 to May 2022 (activity observed over ~3 months) | POLONIUM compromised more than 20 Israeli organizations and one intergovernmental organization with operations in Lebanon. Roughly 80% of the victims ran Fortinet appliances, and Microsoft assesses the group likely gained initial access… | [source](https://www.microsoft.com/en-us/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/) |
| Creepy backdoor family campaign (ESET disclosure) | September 2021 to September 2022 | ESET documented POLONIUM targeting 12+ Israeli organizations across engineering, IT, law, communications, marketing, media, insurance and social services. The group developed at least seven custom backdoors — CreepyDrive and CreepySnail… | [source](https://www.welivesecurity.com/2022/10/11/polonium-targets-israel-creepy-malware/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**42 techniques** across 9 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 25 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 17 hunt-lane techniques
- [`iocs/`](iocs/) — **63 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **42** across 9 tactics
- Lane split: **25 detection / 17 hunt**
- IOCs: **63**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
