# CopyKittens — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Saudi Arabia, Turkey, Jordan  
> **Sectors:** Government, Defense, Academia / research, Information technology / IT services, Municipalities, Journalists and media  
> **Aliases:** CopyKittens, Slayer Kitten, MITRE ATT&CK Group G0052

## Summary

Iran-nexus state-aligned cyber-espionage group operating since at least 2013, assessed by ClearSky and Trend Micro to act in support of Iranian state interests. Attribution to Iran is based on convergence of victimology (Iranian regional adversaries and diaspora/dissident-relevant targets), Persian-language artifacts, operational timezone, and infrastructure/tooling overlap. The group is characterized as technically unsophisticated but persistent — heavily reliant on copied/public code and open-source offensive tooling (hence the 'CopyKittens' name).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Operation Wilted Tulip | 2013 to 2017 (exposed July 2017) | Multi-year cyber-espionage campaign against government, defense, academic, IT and media targets across Israel, Saudi Arabia, Turkey, the U.S., Jordan and Germany. Initial access via strategic web compromise (watering holes on legitimate… | [source](https://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf) |
| CopyKittens Attack Group (ClearSky 2015) | 2013 to 2015 | Earlier ClearSky exposure of the group's espionage against Israeli and regional targets, including compromise of the Jerusalem Post and use of the first-generation Matryoshka RAT, DNS-based C2, and social-engineering lures themed around… | [source](https://www.clearskysec.com/copykitten-jpost/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**41 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 28 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 13 hunt-lane techniques
- [`iocs/`](iocs/) — **125 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **41** across 11 tactics
- Lane split: **28 detection / 13 hunt**
- IOCs: **125**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
