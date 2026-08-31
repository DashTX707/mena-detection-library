# Cadelle — Detection & Hunt Pack

> **Attribution:** Iran-nexus — low-medium confidence  
> **MENA targeting:** Iran, Saudi Arabia, Afghanistan  
> **Sectors:** Individuals (Iranian activists and dissidents), Persian-speaking individuals using anonymizing proxies to bypass censorship, Organizations (unspecified sectors) in Iran and the Middle East  
> **Aliases:** Cadelle, Backdoor.Cadelspy

## Summary

Iran-nexus espionage/surveillance group. Symantec assessed Cadelle as Iran-based on the basis of: operational tempo aligned to the Iranian working week (Saturday–Thursday) and Iran's timezone, Solar Hijri (Persian) calendar date formats embedded in malware strings (a format common in Iran and Afghanistan), and a victimology heavily weighted toward Iranian individuals — activists, dissidents, and users of anonymous proxies to bypass government censorship. This is a targeting/tradecraft-based assessment of nation-state alignment rather than a hard technical link to a specific Iranian government entity.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Cadelspy surveillance campaign against Iranian dissidents and Middle Eastern organizations | Command-and-control registration suggests activity as early as 2011; Symantec monitoring from July 2014 through 2015, with peak infections in September 2015 (nine organizations compromised) | Long-running espionage operation using the custom Windows backdoor Backdoor.Cadelspy (delivered via a dropper) to conduct broad surveillance of individuals and organizations. Cadelspy harvested system information, logged keystrokes,… | [source](https://www.securityweek.com/apparently-linked-iran-spy-groups-target-middle-east/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**8 techniques** across 3 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 2 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 6 hunt-lane techniques
- [`iocs/`](iocs/) — **0 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **8** across 3 tactics
- Lane split: **2 detection / 6 hunt**
- IOCs: **0**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
