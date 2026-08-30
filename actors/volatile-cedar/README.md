# Volatile Cedar — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium-high confidence  
> **MENA targeting:** Israel, Lebanon, Egypt, Saudi Arabia, Jordan, United Arab Emirates  
> **Sectors:** Telecommunications, Internet Service Providers / hosting providers, Defense, Media, IT services, Government  
> **Aliases:** Lebanese Cedar, Volatile Cedar, Explosive Team, MITRE ATT&CK Group G0123 (public MITRE reference only)

## Summary

Lebanon-nexus cyber-espionage actor, assessed with medium-to-high confidence to be linked to the Lebanese political/militant group Hezbollah. Check Point (2015) attributed the campaign to a persistent, well-organized group with a 'possible link to a Lebanese political group' based on operational security discipline, target selection aligned with Lebanese/Hezbollah geopolitical interests, and Arabic-language artifacts; ClearSky (2021) reinforced the Hezbollah linkage. Attribution is analytic (based on victimology, TTP continuity and language artifacts) rather than proven by hard technical indicators; it is not a formal government attribution, so it is treated as medium-high, not high.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Volatile Cedar (original Explosive RAT campaign) | Late 2012 to 2015 | Long-running, low-profile cyber-espionage campaign. Initial access achieved by attacking public-facing web servers via vulnerability scanning and SQL injection, then dropping a JSP web shell used to reconnoiter the target and implant… | [source](https://blog.checkpoint.com/security/volatilecedar/) |
| Lebanese Cedar 2020–2021 resurgence (Explosive v4 / Caterpillar WebShell) | Early 2020 to January 2021 | Resurgent global espionage campaign disclosed by ClearSky. The group exploited known 1-day vulnerabilities on unpatched internet-facing Atlassian (Confluence CVE-2019-3396, Jira CVE-2019-11581) and Oracle 10g (CVE-2012-3152) servers,… | [source](https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**30 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 22 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **31 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **30** across 11 tactics
- Lane split: **22 detection / 8 hunt**
- IOCs: **31**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
