# Group5 — Detection & Hunt Pack

> **Attribution:** Iran-nexus — low confidence  
> **MENA targeting:** Syria, Iran (operator origin / theming, not victim)  
> **Sectors:** Syrian opposition (political activists, negotiators, war-crimes documentarians), Civil society / dissidents  
> **Aliases:** Group5

## Summary

Suspected Iranian nexus. Citizen Lab explicitly frames the Iran connection as an assessment built on convergent-but-circumstantial indicators, NOT a definitive state attribution: operator access to the staging site from Iranian IP space (37.137.131.70, Rightel Communication mobile network), a Persian-language mailer hosted on the malware site, an Iran-based hosting provider (Hostnegar / hostnegar.com), and use of the Iranian-authored 'PAC Crypt' crypter whose debug PDB strings expose the developer alias 'mr.tekide' (linked to crypter.ir / crypting.org and the Ashiyane Digital Security Team). No link to a specific Iranian government entity was established; the operation could be state-linked, contractor, or independent.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| assadcrimes.info — Syrian opposition targeting campaign | October 2015 to May 2016 (site parked May 4, 2016) | A staged malware operation against individuals connected to the Syrian opposition. The actor registered assadcrimes.info (June 2015) — falsely using the identity of Noura Al-Ameer, a former Syrian National Council Vice President and… | [source](https://citizenlab.ca/2016/08/group5-syria/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**15 techniques** across 6 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 6 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 9 hunt-lane techniques
- [`iocs/`](iocs/) — **15 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **15** across 6 tactics
- Lane split: **6 detection / 9 hunt**
- IOCs: **15**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
