# Stealth Falcon — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** United Arab Emirates  
> **Sectors:** Journalists / media, Human-rights activists and defenders, Political dissidents and opposition figures, Civil society  
> **Aliases:** Stealth Falcon, FruityArmor, MITRE ATT&CK group id G0038 (cited as source, not used as actor id)

## Summary

UAE-nexus, state-aligned espionage. Circumstantial evidence (victimology of Emirati journalists/activists/dissidents, the aax.me tracking infrastructure predominantly baiting UAE political content, and Project Raven operational overlap reported separately) links Stealth Falcon to United Arab Emirates government interests, but a direct state link has not been publicly confirmed to high confidence. Assessed medium-high confidence as UAE-aligned.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Spear-phishing of Emirati journalists, activists and dissidents (aax.me tracking + malicious macro documents) | 2012 to 2016 | Long-running targeted-spyware operation against Emirati journalists, human-rights activists and dissidents. Operators built fictitious organizations ('The Right to Fight') and fake personas (e.g. journalist 'Andrew Dwight') to build… | [source](https://citizenlab.ca/2016/05/stealth-falcon/) |
| Win32/StealthFalcon BITS-abusing backdoor | 2015 to 2019 | ESET analyzed a distinctive backdoor (Win32/StealthFalcon) attributed to the group whose PowerShell-based capabilities overlap the 2016 Citizen Lab implant. Its signature behavior is the abuse of the Windows Background Intelligent… | [source](https://www.welivesecurity.com/2019/09/09/backdoor-stealth-falcon-group/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**36 techniques** across 10 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 26 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **32 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **36** across 10 tactics
- Lane split: **26 detection / 10 hunt**
- IOCs: **32**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
