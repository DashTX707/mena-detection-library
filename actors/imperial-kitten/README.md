# Imperial Kitten — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Mediterranean / Eastern Mediterranean maritime routes  
> **Sectors:** Transportation, Logistics, Maritime / shipping, Technology, Defense, Energy  
> **Aliases:** Imperial Kitten, CURIUM, Yellow Liderc, TA456, Crimson Sandstorm

## Summary

Iran-nexus, assessed with moderate confidence to operate in support of Iranian state interest and likely aligned with the Islamic Revolutionary Guard Corps (IRGC). CrowdStrike tracks the group as IMPERIAL KITTEN, active since at least 2017, conducting cyber-espionage and enabling operations primarily against Israeli organizations. There is meaningful overlap with clusters other vendors call Tortoiseshell/Crimson Sandstorm/TA456; the overlap is noted honestly, but the IMAPLoader-centric activity here is treated as its own Imperial Kitten/Yellow Liderc cluster.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Israeli strategic web compromise (watering-hole) campaign | 2022 to 2023 | The actor compromised legitimate Israeli websites and embedded malicious JavaScript that beaconed visitor details (public IP, screen/browser data) to actor-controlled infrastructure, in several cases via the Matomo open-source analytics… | [source](https://www.crowdstrike.com/en-us/blog/imperial-kitten-deploys-novel-malware-families/) |
| IMAPLoader / StandardKeyboard email-C2 espionage | 2022 to 2023 (IMAP implant lineage from late 2021) | Follow-on intrusions delivered IMAPLoader, a .NET DLL implant that uses AppDomainManager injection and communicates entirely over IMAP email (Yandex mailboxes) for tasking and payload retrieval, and StandardKeyboard, an email-C2 implant… | [source](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**35 techniques** across 12 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 25 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **83 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **35** across 12 tactics
- Lane split: **25 detection / 10 hunt**
- IOCs: **83**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
