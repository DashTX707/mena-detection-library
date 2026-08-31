# Ballistic Bobcat — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, United Arab Emirates  
> **Sectors:** Automotive, Manufacturing, Engineering, Financial services / insurance, Media / communications, Healthcare  
> **Aliases:** Ballistic Bobcat, APT35-adjacent (ESET-tracked activity group), Sponsor (backdoor operator)

## Summary

Iran-aligned activity group. ESET tracks Ballistic Bobcat as a distinct cluster whose activity overlaps with the group publicly reported as APT35 / Charming Kitten / Phosphorus / Mint Sandstorm. The overlap is acknowledged honestly rather than collapsed into a single identity — infrastructure, victimology (Israel-heavy), and the Sponsor backdoor are the ESET-tracked basis.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Sponsoring Access (Sponsor backdoor campaign) | September 2021 to April 2022 (Sponsor deployments; related tooling from mid-2021) | Ballistic Bobcat compromised at least 34 organizations — ~31 in Israel plus one each in Brazil and the UAE — via scan-and-exploit of internet-facing Microsoft Exchange servers (ProxyLogon/ProxyShell-era, CVE-2021-26855). On vulnerable… | [source](https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**31 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 26 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 5 hunt-lane techniques
- [`iocs/`](iocs/) — **19 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **31** across 13 tactics
- Lane split: **26 detection / 5 hunt**
- IOCs: **19**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
