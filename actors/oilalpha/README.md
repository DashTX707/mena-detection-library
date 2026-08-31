# OilAlpha — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Yemen, Saudi Arabia, United Arab Emirates  
> **Sectors:** Humanitarian aid / relief organizations, Human rights organizations, Non-governmental organizations (NGOs), Media and journalists, Development sector, Government / political representatives and negotiation delegates  

## Summary

Yemen-nexus. Recorded Future Insikt Group assesses OilAlpha is LIKELY a group operating in support of a pro-Houthi movement agenda; attribution is an analytic assessment, not confirmed state control. Supporting (but non-conclusive) indicators: the group's C2 and delivery infrastructure was almost exclusively associated with IP ranges of the Public Telecommunication Corporation (PTC), a Yemeni government-owned enterprise reported to be under the direct control of the Houthi authorities; near-exclusive reliance on dynamic DNS; Arabic-language lures; and victimology (humanitarian aid control, Saudi-Yemen negotiation delegates) aligned with Houthi interests.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| OilAlpha Android RAT campaign against Arabian Peninsula entities | May 2022 to 2023 (first disclosed 2023-05) | Ongoing campaign delivering malicious Android APKs via WhatsApp social engineering (Saudi Arabian phone numbers, URL link shorteners) to political/government representatives, media personalities, journalists, and… | [source](https://www.recordedfuture.com/research/oilalpha-likely-pro-houthi-group-targeting-arabian-peninsula) |
| OilAlpha humanitarian-aid targeting cluster (CTA-2024-0709) | Early-to-mid 2024 (samples from June 2024; disclosed 2024-07-09) | New cluster of malicious mobile applications and supporting infrastructure almost certainly tied to OilAlpha, used to target at least three globally recognized humanitarian organizations: CARE International, the Norwegian Refugee… | [source](https://assets.recordedfuture.com/insikt-report-pdfs/2024/cta-2024-0709.pdf) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**13 techniques** across 8 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 5 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **28 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **13** across 8 tactics
- Lane split: **5 detection / 8 hunt**
- IOCs: **28**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
