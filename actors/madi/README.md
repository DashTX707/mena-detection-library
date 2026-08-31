# Madi — Detection & Hunt Pack

> **Attribution:** Iran-nexus — low-medium confidence  
> **MENA targeting:** Iran, Israel, United Arab Emirates, Saudi Arabia  
> **Sectors:** Critical infrastructure engineering firms, Government, Financial services, Academia / education, Engineering  
> **Aliases:** Madi, Mahdi

## Summary

MENA-focused cyber-espionage campaign active from approximately September 2011 through mid/late 2012, jointly discovered and sinkholed by Kaspersky Lab and the Israeli firm Seculert. Victimology (roughly 800 victims heavily concentrated in Iran, plus Israel, Afghanistan/Pakistan and the wider Middle East, targeting critical-infrastructure engineering firms, government agencies, financial institutions and academia) together with the presence of numerous Persian-language strings in the malware and the custom C# server-manager tooling led open-source analysts to speculate about an Iran-nexus. However, neither Kaspersky nor Seculert asserted a firm state sponsor: the Persian strings and Iranian victim concentration are ambiguous (an operator targeting Iran would plausibly also be Persian-literate), and no infrastructure, contractor, or government linkage was ever established.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| The Madi Campaign | September 2011 – July 2012 (peak downloader creation December 2011, February–March 2012, June 2012) | Info-stealing espionage operation delivered via social engineering rather than exploits. Victims received weaponized PowerPoint slideshow (.pps) files (e.g. 'Magic_Machine1123.pps', 'Moses_pic1.pps') using PowerPoint 'Activated Content'… | [source](https://securelist.com/the-madi-campaign-part-i-5/33693/) |
| Mahdi resurrected variant | September 2012 | After the original C2 domains were sinkholed, Seculert and Kaspersky reported a new Mahdi variant with code optimizations and, notably, the ability to operate without contacting a C2 for orders — allowing operations to continue after… | [source](https://www.securityweek.com/mahdi-malware-resurrected-cuts-ties-cc-servers/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**14 techniques** across 7 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 8 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 6 hunt-lane techniques
- [`iocs/`](iocs/) — **4 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **14** across 7 tactics
- Lane split: **8 detection / 6 hunt**
- IOCs: **4**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
