# Tortoiseshell (G0139) — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium-high confidence  
> **MENA targeting:** Saudi Arabia, Israel, United Arab Emirates, Kuwait, Bahrain, Qatar  
> **Sectors:** IT / managed service providers (supply-chain pivot), Maritime / shipping, Transportation & logistics, Defense / aerospace, Technology, Energy  
> **Aliases:** Tortoiseshell, Smoke Sandstorm, Cuboid Sandstorm, DEV-0056, DEV-0228, Operation Tortoiseshell

## Summary

Iran-nexus; assessed to operate on behalf of the Iranian state with a suspected nexus to the Islamic Revolutionary Guard Corps (IRGC). Active since at least 2018 (Symantec, first Saudi IT-provider supply-chain wave) through 2024, per Symantec/Broadcom, CrowdStrike (IMPERIAL KITTEN) and PwC (Yellow Liderc).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Saudi IT-provider supply-chain compromise | 2018 to 2019 | Compromised at least 11 organizations, majority in Saudi Arabia, focusing on IT providers to reach downstream customers via a trusted-relationship / supply-chain pivot. Deployed Backdoor.Syskit (a basic .NET/Delphi downloader-backdoor)… | [source](https://www.security.com/threat-intelligence/tortoiseshell-apt-supply-chain) |
| IMPERIAL KITTEN social-engineering & malware operations | 2017 to 2024 | Job-recruitment-themed social engineering and fake personas used to deliver custom .NET implants; strategic web compromise (watering hole) and, in some intrusions, SQL injection of public-facing apps for initial access; publicly… | [source](https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/) |
| Yellow Liderc / IMAPLoader watering-hole campaign | 2022 to 2023 | Strategic web compromises injecting bespoke JavaScript into legitimate (primarily Israel-related, maritime/shipping/logistics) websites to fingerprint visitors and exfiltrate host information to attacker-controlled domains, leading to… | [source](https://www.crowdstrike.com/en-us/adversaries/imperial-kitten/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**74 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 48 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 26 hunt-lane techniques
- [`iocs/`](iocs/) — **6 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **74** across 13 tactics
- Lane split: **48 detection / 26 hunt**
- IOCs: **6**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
