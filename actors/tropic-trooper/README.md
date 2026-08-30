# Tropic Trooper — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Middle East (government entity, 2024), Middle East (regional human-rights subject matter targeted via a Malaysian study)  
> **Sectors:** Government, Government (human-rights / studies related to the Middle East), Transportation, Healthcare, High-tech / technology, Content-management / public-facing web hosting  
> **Aliases:** KeyBoy, Pirate Panda, Earth Centaur, APT23, MITRE ATT&CK G0081

## Summary

China-nexus cyber-espionage group active since at least 2011, assessed Chinese-speaking based on code artifacts, tooling (China Chopper, Fscan, Neo-reGeorg, Godzilla, mimikatz-via-Swor) and target selection aligned with PRC strategic interest. Kaspersky and Trend Micro track it as Tropic Trooper / Earth Centaur; MITRE catalogs it as G0081. Attribution to a China-nexus state-aligned actor is medium-to-high confidence (converging vendor assessments, tradecraft and victimology) but no single government advisory names a specific PRC entity, so specific-unit attribution remains unconfirmed.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Middle East government entity — Umbraco China Chopper web shell + Crowdoor loader | June 2023 – 2024 (activity surfaced June 2024) | Persistent intrusion into a Middle East government entity's public-facing Umbraco (open-source .NET CMS) web server. Kaspersky telemetry flagged recurring alerts for a new China Chopper web-shell variant compiled as a .NET Umbraco… | [source](https://securelist.com/new-tropic-trooper-web-shell-infection/113737/) |
| Earth Centaur — transportation & government (ProxyShell/IIS) | 2020 – 2021 | Long-running espionage against transportation companies and transportation-related government agencies. Initial access via vulnerable Microsoft Exchange (ProxyLogon/ProxyShell) and IIS servers, followed by China Chopper web shells and… | [source](https://www.trendmicro.com/en_us/research/21/l/collecting-in-the-dark-tropic-trooper-targets-transportation-and-government-organizations.html) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**35 techniques** across 14 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 25 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **29 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **35** across 14 tactics
- Lane split: **25 detection / 10 hunt**
- IOCs: **29**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
