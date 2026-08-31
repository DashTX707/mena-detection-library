# Ferocious Kitten — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Iran  
> **Sectors:** Individuals / dissidents / activists (Persian-speaking Iranian citizens), Civil society / opposition, Journalists and regime critics (inferred from decoy themes)  
> **Aliases:** Ferocious Kitten

## Summary

Iran-nexus, domestically focused cyber-espionage / surveillance group active since at least 2015, targeting Persian-speaking individuals — apparently Iranian dissidents, activists and opposition figures — who appear to be located inside Iran. Decoy content (anti-regime Persian political messaging, imagery of protests and political prisoners) is designed to lure the regime's own opponents, and interface/repository text, Persian keyboard-layout gating and Persian file names are consistent with an operator serving Iranian domestic-surveillance interests. Kaspersky observed TTP overlap with the Iran-based Domestic Kitten (APT-C-50) operation but treats Ferocious Kitten as a distinct cluster and did not attribute it to a named government entity or established APT group.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Persian-dissident surveillance campaign (MarkiRAT) | 2015 to 2021 (2021 decoy documents observed by Kaspersky) | Multi-year covert surveillance of Persian-speaking targets in Iran using the custom MarkiRAT Windows implant. Delivery via macro-weaponized Persian-language Word documents whose decoy content references anti-regime protest and political… | [source](https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**22 techniques** across 8 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 14 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **55 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **22** across 8 tactics
- Lane split: **14 detection / 8 hunt**
- IOCs: **55**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
