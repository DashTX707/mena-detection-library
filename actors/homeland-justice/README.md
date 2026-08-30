# Homeland Justice — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** Israel  
> **Sectors:** Government (national / public administration), Public services and critical government IT systems, Israel-linked private-sector and organizational targets  
> **Aliases:** Homeland Justice, Storm-0842, DEV-0842, Karma (leak persona), HomeLand Justice

## Summary

Iran-nexus destructive and hack-and-leak operation publicly assessed by CISA/FBI and Microsoft to be conducted by Iranian state cyber actors sponsored by the Ministry of Intelligence and Security (MOIS). 'Homeland Justice' is the public-facing persona (Telegram channel and leak website) used to claim, message, and leak stolen data following destructive intrusions. Microsoft tracks the destructive-operations actor as Storm-0842 (formerly DEV-0842); Check Point associates the Homeland Justice/Karma persona with the Void Manticore cluster.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Destructive attack on the Government of Albania (ROADSWEEP + No-Justice wiper) | Initial access ~May 2021; destructive attack July 15, 2022; follow-on Sept 2022 | The actor gained initial access ~14 months prior by exploiting an internet-facing Microsoft SharePoint server (CVE-2019-0604), then maintained long dwell using .aspx web shells (ClientBin.aspx / App_Web_bckwssht.dll), RDP/VPN with… | [source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a) |
| Void Manticore / Homeland Justice-Karma destructive activity against Israel-linked targets | 2022 to 2024 | Check Point ties the Homeland Justice persona and the Karma leak brand to Void Manticore, a MOIS-linked destructive cluster conducting hack-and-leak and wiping operations against Israeli targets, sometimes handed access from a separate… | [source](https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**34 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 24 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **30 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **34** across 13 tactics
- Lane split: **24 detection / 10 hunt**
- IOCs: **30**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
