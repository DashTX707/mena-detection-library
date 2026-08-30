# SideWinder — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Egypt, United Arab Emirates, Saudi Arabia, Djibouti, Jordan, Bahrain  
> **Sectors:** Maritime / ports / port authorities / logistics, Government and diplomatic entities, Military and defense, Nuclear energy / nuclear power plants / energy, Telecommunications, Financial institutions  
> **Aliases:** Rattlesnake, T-APT-04, APT-C-17, Razor Tiger, BabyElephant, Hardcore Nationalist (HN2), MITRE ATT&CK G0121

## Summary

India-nexus, suspected state-aligned espionage actor active since at least 2012, historically focused on Pakistan, China, Nepal, Afghanistan and the wider South Asia region against government, military and diplomatic targets. Assessed India-aligned by multiple vendors (Kaspersky, BlackBerry, Trend Micro) on the basis of targeting (persistent focus on Pakistani and Chinese military/diplomatic entities), lure content, and operational tempo; the nexus is a medium-high-confidence assessment rather than a government-confirmed attribution, and no vendor claims a specific sponsoring entity. From 2023 into 2024–2025 the group markedly EXPANDED beyond South Asia into the Middle East and Africa, adding maritime/port authorities, nuclear energy agencies, government/diplomatic, logistics, energy and telecom targets across Egypt, the UAE, Saudi Arabia, Djibouti, Jordan, Bahrain and the wider region — the reason for inclusion in the MENA Detection Library.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Middle East & Africa expansion — StealerBot espionage campaign | 2023–2024 (documented by Kaspersky October 2024) | SideWinder expanded operations into the Middle East and Africa, hitting government, military, logistics, infrastructure, telecom, financial, university and oil-trading entities across Djibouti, Egypt, the UAE, Saudi Arabia, Jordan,… | [source](https://securelist.com/sidewinder-apt-updates-its-toolset-and-targets-nuclear-sector/115847/) |
| Maritime / port-authority targeting (Mediterranean, Red Sea, Indian Ocean) | 2024 (BlackBerry July 2024; Kaspersky October 2024) | SideWinder intensified attacks on maritime facilities and port authorities, including the first observed strikes on maritime targets in the Mediterranean. Lure documents falsified communications from specific ports (e.g. the Port of… | [source](https://www.darkreading.com/cyberattacks-data-breaches/sidewinder-intensifies-attacks-maritime-sector) |
| Nuclear-sector and critical-infrastructure targeting with updated toolset | H2 2024 – 2025 (Securelist / The Hacker News March 2025) | SideWinder broadened targeting to entities associated with nuclear energy, using lure documents referencing nuclear power plants and nuclear energy agencies, alongside continued maritime, telecom, real-estate and hospitality targeting.… | [source](https://thehackernews.com/2025/03/sidewinder-apt-targets-maritime-nuclear.html) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**46 techniques** across 12 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 39 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 7 hunt-lane techniques
- [`iocs/`](iocs/) — **48 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **46** across 12 tactics
- Lane split: **39 detection / 7 hunt**
- IOCs: **48**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
