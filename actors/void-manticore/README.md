# Void Manticore — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** Israel  
> **Sectors:** Government, Public sector / national statistics (INSTAT Albania), Critical infrastructure, Enterprises / high-value Israeli organizations (40+ claimed by Karma)  
> **Aliases:** Void Manticore, Storm-1084, Karma

## Summary

Iranian threat actor affiliated with the Ministry of Intelligence and Security (MOIS), per Check Point Research and Microsoft (tracked as Storm-0842). A destructive + influence actor that combines custom wiper deployment with hack-and-leak psychological operations. Check Point documents a systematic 'handoff' in which Scarred Manticore (Storm-0861) performs initial access, long-dwell espionage and email exfiltration, then transfers the compromised victim (web shells + Domain Admin credentials) to Void Manticore, which executes the destructive phase.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Albania destructive attacks (Homeland Justice) | July 2022; recurring late 2023 and early 2024 | Storm-0861 (Scarred Manticore) obtained initial access via CVE-2019-0604 and exfiltrated email, then handed off to Void Manticore, which deployed the Cl Wiper (cl.exe abusing the ElRawDisk rwdsk.sys driver) plus ransomware, leaking data… | [source](https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/) |
| Israel destructive + leak campaign (Karma / BiBi wiper) | October 2023 through 2024 | Following Scarred Manticore initial access via CVE-2019-0604 and email exfiltration (LionHead/LionTail), Void Manticore was handed the victims and deployed the custom BiBi wiper (BiBi-Linux-Wiper bibi-linux.out and BiBi-Windows-Wiper… | [source](https://research.checkpoint.com/2024/bad-karma-no-justice-void-manticore-destructive-activities-in-israel/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**21 techniques** across 9 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 12 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 9 hunt-lane techniques
- [`iocs/`](iocs/) — **13 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **21** across 9 tactics
- Lane split: **12 detection / 9 hunt**
- IOCs: **13**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
