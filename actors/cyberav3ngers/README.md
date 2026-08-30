# CyberAv3ngers — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** Israel  
> **Sectors:** Water and Wastewater Systems (WWS), Energy, Fuel management systems (gas stations / fuel pumps), Food and beverage manufacturing, Transportation / shipping and distribution, Healthcare  
> **Aliases:** CyberAv3ngers, CyberAveng3rs, Cyber Avengers

## Summary

Iranian IRGC-affiliated cyber persona assessed by CISA/FBI and Claroty to be operated by the Islamic Revolutionary Guard Corps Cyber-Electronic Command (IRGC-CEC). Active under the CyberAv3ngers persona since 2020 with hacktivist-style Telegram claims (several false), escalating to genuine OT/ICS compromise of internet-exposed Unitronics Vision-series PLCs/HMIs at water/wastewater and other critical-infrastructure sites in Israel and the United States from late 2023, and in 2024 to the custom IOCONTROL/OrpaCrypt Linux IoT/OT malware platform. The IRGC is designated a foreign terrorist organization by the U.S.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Unitronics Vision-series PLC/HMI defacement campaign | 2023-11 to 2024-01 (four assessed waves) | Under the CyberAv3ngers persona, IRGC-CEC actors compromised internet-exposed Unitronics Vision Series PLCs/HMIs by authenticating to the default TCP port 20256 using default or no password. They compromised at least 75 devices (>=34 in… | [source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a) |
| IOCONTROL / OrpaCrypt IoT-OT malware operation (Orpak/Gasboy fuel systems) | 2024 (domain registered 2023-11-23) | CyberAv3ngers deployed IOCONTROL (aka OrpaCrypt), a custom modular Linux malware platform for IoT/OT devices (IP cameras, routers, PLCs, HMIs, firewalls, fuel systems) from vendors including Baicells, D-Link, Hikvision, Red Lion, Orpak,… | [source](https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**20 techniques** across 9 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 12 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **4 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **20** across 9 tactics
- Lane split: **12 detection / 8 hunt**
- IOCs: **4**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
