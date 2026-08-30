# UNC3890 — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel  
> **Sectors:** Shipping / maritime, Government, Energy, Healthcare, Aviation, Defense  
> **Aliases:** UNC3890, Operation Sugarush (campaign name)

## Summary

Suspected Iran-nexus. Mandiant assesses with MEDIUM confidence that UNC3890 is linked to Iran, based on: use of a Farsi-language artifact in SUGARDUMP (the .NET project name 'yaal' — Farsi for a horse's mane — and an AES password string containing 'KHODA', Farsi for 'God'); consistent targeting of Israeli shipping, government, energy, healthcare, aviation and defense entities aligning with Iranian strategic interest; and possible weak overlaps with prior Iranian activity. Mandiant did not tie UNC3890 to a specific named Iranian group.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Operation Sugarush (UNC3890 Israeli-shipping espionage cluster) | Late 2020 through mid-2022 (SUGARDUMP versions from early 2021; ongoing at time of publication August 2022) | Espionage-motivated intrusion set against Israeli shipping/maritime, government, energy, healthcare, aviation and defense targets. Initial access via (1) an elaborate email social-engineering effort using fake job offers (e.g., a… | [source](https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-actor-targeting-israeli-shipping) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**32 techniques** across 9 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 22 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **45 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **32** across 9 tactics
- Lane split: **22 detection / 10 hunt**
- IOCs: **45**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
