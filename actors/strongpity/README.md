# StrongPity — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Turkey, Syria (including Kurdish targets), North Africa (broader MENA)  
> **Sectors:** Individuals of intelligence interest (Kurdish community, activists), Users of encryption / privacy software, Organizations of intelligence interest, Espionage targets (undifferentiated by industry vertical)  
> **Aliases:** StrongPity, PROMETHIUM, APT-C-41, StrongPity2, MITRE ATT&CK group id G0056 (cited as source only, not the actor id), MITRE ATT&CK software id S0491 (StrongPity malware)

## Summary

Türkiye-nexus, assessed state-aligned. StrongPity/PROMETHIUM is an espionage activity group active since at least 2012 with a heavy emphasis on Turkish and Syrian (notably Kurdish) targets, plus operations against individuals and organizations of intelligence interest in Italy, Belgium, North Africa and the broader MENA/Europe region. Bitdefender's 2020 victimology placed the majority of victims along the Turkey–Syria border and in Istanbul, consistent with interest in the Turkey–Kurdish geopolitical conflict; ESET's 2017 findings of delivery via ISP-level redirection (a capability that generally requires provider-level cooperation or access) further support a state-aligned assessment.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Italian & Belgian encryption-user watering holes (WinRAR / TrueCrypt) | 2016 (reported October 2016) | StrongPity redirected users seeking encryption/archiving software to actor-controlled typosquat sites (ralrab[.]com mimicking rarlab.com; winrar[.]it, winrar[.]be; true-crypt[.]com replicating the TrueCrypt site, with victims funneled… | [source](https://securelist.com/on-the-strongpity-waterhole-attacks-targeting-italian-and-belgian-encryption-users/76147/) |
| ISP-level redirection campaign (StrongPity2, replacing FinFisher) | 2017 (reported December 2017) | ESET observed a StrongPity variant delivered via man-in-the-middle / HTTP on-the-fly browser redirection most likely operating at the ISP level in two countries: victims downloading legitimate applications (CCleaner v5.34, Driver… | [source](https://www.welivesecurity.com/2017/12/08/strongpity-like-spyware-replaces-finfisher/) |
| Kurdish-aimed trojanized-tools campaign (Turkey/Syria) | 2018–2020 (Bitdefender whitepaper June 2020) | StrongPity trojanized a broad set of legitimate tools (archivers, file-recovery, remote-connection utilities, and even security software — e.g. WinRAR, 7-Zip, WinBox, and others) and selectively delivered them to pre-defined IP lists… | [source](https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**38 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 24 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 14 hunt-lane techniques
- [`iocs/`](iocs/) — **22 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **38** across 11 tactics
- Lane split: **24 detection / 14 hunt**
- IOCs: **22**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
