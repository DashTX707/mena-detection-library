# HEXANE (G1001) — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Saudi Arabia, Kuwait, United Arab Emirates, Morocco, Tunisia  
> **Sectors:** Oil & gas / energy, Telecommunications, Aviation, Internet Service Providers  
> **Aliases:** Lyceum, Siamesekitten, Spirlin

## Summary

Iran-nexus cyber-espionage group active since at least 2017; targets energy, oil & gas, telecommunications, aviation and ISP organizations across the Middle East and Africa. TTPs resemble APT33 and OilRig but victimology and toolset differentiate it as a distinct cluster.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| LYCEUM Middle East campaign (DanBot) | 2018-2019 | Campaign against Middle Eastern oil & gas and telecommunications organizations using the DanBot backdoor, which supports both DNS-tunneling and HTTP-based C2. Initial access via password spraying and spearphishing with macro-laden Excel… | [source](https://www.secureworks.com/research/lyceum-takes-center-stage-in-middle-east-campaign) |
| Siamesekitten / Lyceum campaign vs. Israeli targets | 2021 | Impersonation of a legitimate HR/IT firm via fake LinkedIn personas and a spoofed careers website to lure IT and communications personnel at Israeli organizations; delivered Milan and DanBot implants. | [source](https://www.clearskysec.com/siamesekitten/) |
| Marlin / Shark backdoor campaign | 2021 | Later-stage espionage tooling (Milan, Shark, Marlin) targeting diplomatic and technology organizations; Marlin abuses Microsoft OneDrive/Graph API for bidirectional C2 while Shark uses DNS and HTTP. | [source](https://www.welivesecurity.com/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**63 techniques** across 13 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 43 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 20 hunt-lane techniques
- [`iocs/`](iocs/) — **30 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **63** across 13 tactics
- Lane split: **43 detection / 20 hunt**
- IOCs: **30**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
