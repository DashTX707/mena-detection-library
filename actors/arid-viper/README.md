# Arid Viper — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Palestinian Territories, Israel, Egypt, Saudi Arabia, Wider Arabic-speaking Middle East  
> **Sectors:** Government, Military and security personnel, Political activists and dissidents, Education / academia, Journalists and media, Law enforcement  
> **Aliases:** APT-C-23, Desert Falcon, Mantis, Two-tailed Scorpion, Grey Karkadann, TAG-63, Big Bang APT, G1028 (public MITRE ATT&CK group id)

## Summary

Palestinian-nexus, espionage- and politically-motivated APT active since at least 2014, tracked by MITRE as APT-C-23 (G1028). Multiple vendors (Meta/Facebook, SentinelLabs, Cisco Talos) assess Arid Viper as aligned with Palestinian/Hamas interests, though a definitive state/organizational sponsor is not publicly confirmed with high certainty. The group runs parallel Windows (Micropsia lineage) and Android (SpyC23/VAMP/FrozenCell) espionage operations.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| SpyC23 Android spyware — fake Telegram / Skipped Messenger (App-Upgrade) | 2022 to 2023 | Arid Viper delivered newer SpyC23 Android spyware versions to Arabic-speaking targets via weaponized apps posing as Telegram and a romance-themed messaging app called Skipped (internally APP-UPGRADE). Apps used lengthy in-app permission… | [source](https://www.sentinelone.com/labs/arid-viper-apts-nest-of-spyc23-malware-continues-to-target-android-devices/) |
| Fake app-update Android spyware with YouTube lures | 2023 to 2024 | Arid Viper disguised mobile spyware as updates for legitimate Android apps (WhatsApp, Messenger, Instagram, Google Play, Signal), distributing APK links via Arabic-language (Levantine-dialect) YouTube tutorial videos. Malware disabled… | [source](https://blog.talosintelligence.com/arid-viper-mobile-spyware/) |
| Mantis Windows espionage against Palestinian targets (Micropsia / Arid Gopher) | September 2022 to February 2023 | Symantec observed Mantis (Arid Viper) using updated Micropsia and Arid Gopher backdoors against organizations in the Palestinian territories, deploying three distinct toolset variants across three groups of computers to compartmentalize… | [source](https://www.security.com/threat-intelligence/mantis-palestinian-attacks) |
| PyMicropsia information-stealing trojan | 2020 | Unit 42 documented PyMICROPSIA, a Python-based (PyInstaller-packaged) evolution of Micropsia with modular payloads for keylogging, screenshotting, browser-credential theft, USB monitoring and RAR-based file exfiltration over HTTP C2,… | [source](https://unit42.paloaltonetworks.com/pymicropsia/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**40 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 22 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 18 hunt-lane techniques
- [`iocs/`](iocs/) — **50 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **40** across 11 tactics
- Lane split: **22 detection / 18 hunt**
- IOCs: **50**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
