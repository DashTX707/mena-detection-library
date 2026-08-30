# UNC1549 — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, United Arab Emirates, Turkey, Qatar (Azure regions and lures reference Qatar-hosted infrastructure), Broader Middle East  
> **Sectors:** Aerospace, Aviation / airlines, Defense industrial base, Defense contractors and their third-party vendors/suppliers  
> **Aliases:** TA455 (Proofpoint), Smoke Sandstorm (Microsoft; formerly Bohrium), Yellow Dev 13, Overlaps with Tortoiseshell / Imperial Kitten / TA456 / Crimson Sandstorm / Curium / Yellow Liderc, 'Iranian Dream Job' activity cluster

## Summary

Suspected Iran-nexus espionage actor, assessed by Mandiant/GTIG with MEDIUM confidence to be aligned with Iranian state interests and overlapping with the IRGC-affiliated Tortoiseshell/Crimson Sandstorm ecosystem. Attribution is deliberately hedged: Mandiant tracks the cluster as UNC1549 (an uncategorized group) and notes TTP/victimology overlap with Smoke Sandstorm and Crimson Sandstorm but does not make a high-confidence IRGC identity call. Proofpoint tracks a substantially overlapping cluster as TA455.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Fake-recruitment spearphishing against Israeli/Middle East aerospace & defense (MINIBIKE / MINIBUS) | June 2022 to February 2024 (ongoing at time of first report) | Spearphishing emails delivering links to actor-controlled fake job-recruitment websites and Israel-Hamas conflict-themed lure sites. Fake login pages mimicking legitimate companies harvest credentials; malicious payloads deploy the… | [source](https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-unc1549-targets-israel-middle-east) |
| Expanded aerospace/defense ecosystem intrusions via third-party access (GTIG Frontline) | 2024 to 2025 | GTIG documents a surge in UNC1549 operations pivoting into aerospace/defense targets through compromised third-party vendor, contractor and partner accounts, abusing Citrix, VMware, and Azure Virtual Desktop (AVD) with VDI-breakout… | [source](https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**40 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 32 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **80 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **40** across 13 tactics
- Lane split: **32 detection / 8 hunt**
- IOCs: **80**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
