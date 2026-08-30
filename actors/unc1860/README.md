# UNC1860 — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Saudi Arabia, United Arab Emirates, Qatar, Iraq, Gulf states (broadly)  
> **Sectors:** Government, Telecommunications, Military / defense, IT services / internet-facing server operators  
> **Aliases:** UNC1860

## Summary

Iran-nexus actor assessed with moderate confidence to be affiliated with Iran's Ministry of Intelligence and Security (MOIS), functioning as a specialized initial-access broker / persistent-access enabler rather than an end-effects actor. UNC1860 opportunistically compromises high-value government and telecommunications networks across the Middle East, establishes durable passive footholds, and hands reliable remote access to other Iranian actors (Storm-0861/Scarred Manticore, and destructive/wiper operators). Attribution rests on victimology aligned with MOIS interests, a large purpose-built library of passive GUI-operated implants and specialized tooling, and repeated victim overlap with APT34/OilRig.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Persistent-access brokering into Middle Eastern government and telecom networks ('Temple of Oats') | Activity observed 2020-2024 (reported 2024-09-19) | UNC1860 opportunistically exploits internet-facing servers, deploys droppers (SASHEYAWAY) and webshells (STAYSHANTE, BASEWALK), and installs a library of passive, GUI-operated implants — chiefly TEMPLEDOOR (operated via the .NET… | [source](https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html) |
| VIROGREEN SharePoint exploitation framework (CVE-2019-0604) | 2019-2020 and later (reported 2024-09-19) | VIROGREEN is a custom post-exploitation framework used to exploit vulnerable Microsoft SharePoint servers via CVE-2019-0604. It bundles vulnerability scanning, control of the STAYSHANTE webshell and BASEWALK backdoor, and orchestration… | [source](https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**30 techniques** across 12 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 11 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 19 hunt-lane techniques
- [`iocs/`](iocs/) — **43 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **30** across 12 tactics
- Lane split: **11 detection / 19 hunt**
- IOCs: **43**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
