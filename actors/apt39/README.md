# APT39 (G0087) — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** Iran (domestic dissidents/persons of interest), Saudi Arabia, United Arab Emirates, Kuwait, Qatar, Bahrain  
> **Sectors:** Telecommunications, Travel & tourism / hospitality, Academia / higher education, Government, Technology / IT, Aviation  
> **Aliases:** APT39, Chafer, Remix Kitten, ITG07, Cobalt Hickman, Rana Intelligence Computing

## Summary

Iran-nexus; cyber espionage activity conducted by Iran's Ministry of Intelligence and Security (MOIS) through the front company Rana Intelligence Computing since at least 2014, per MITRE ATT&CK G0087, FireEye/Mandiant (2019), and the September 2020 U.S. Government actions (FBI FLASH, DOJ indictments, and OFAC sanctions designating Rana Intelligence Computing and named individuals). APT39 focuses on personal-information tracking and surveillance of individuals and entities considered a threat by the MOIS.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| APT39 personal-information tracking operations | 2014-present | Long-running MOIS surveillance operations prioritizing monitoring, tracking, and surveillance of specific individuals. Heavy targeting of telecommunications and travel/tourism sectors (which hold PII, travel records, and… | [source](https://attack.mitre.org/groups/G0087/) |
| Chafer telecom & travel intrusions (Gulf focus) | 2015-2018 | Symantec/Bitdefender-tracked Chafer activity against telecommunications and travel companies in the Middle East, using spear-phishing, SQL injection against public-facing servers, web shells (ANTAK, ASPXSpy), and post-exploitation… | [source](https://attack.mitre.org/groups/G0087/) |
| Rana Intelligence Computing designation | 2020-09 | U.S. Treasury OFAC sanctioned Rana Intelligence Computing Company as a MOIS front for APT39; DOJ unsealed indictments and the FBI released a FLASH (CU-000151-MW) detailing malware and TTPs. Confirmed the MOIS/Rana operational link and… | [source](https://www.cisa.gov/news-events/analysis-reports/ar20-259a) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**53 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 43 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **0 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **53** across 11 tactics
- Lane split: **43 detection / 10 hunt**
- IOCs: **0**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
