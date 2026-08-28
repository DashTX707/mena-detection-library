# <Actor Name> (<MITRE ID>) — Detection & Hunt Pack

> **Attribution:** <sponsor / nexus> — <confidence>
> **MENA targeting:** <countries> · **Sectors:** <sectors>
> **Aliases:** <aliases>

## Summary

<2–4 sentences: who they are, why MENA defenders care, what tradecraft this pack covers.>

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| | | | |

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap
- [`detections/`](detections/) — Sigma rules for detectable TTPs
- [`hunts/`](hunts/) — hunt hypotheses for TTPs that aren't cleanly detectable
- [`iocs/`](iocs/) — publicly-sourced indicators
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (extract) → `decision-agent` (route) → `detection-engineer` (Sigma) + `threat-hunter` (hunts).
Sources cited inline and in `intel/cti-pipeline.json`.

## Coverage snapshot

- TTPs mapped: **N**
- Detections: **N** · Hunts: **N** · IOCs: **N**
