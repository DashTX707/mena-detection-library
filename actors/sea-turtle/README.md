# Sea Turtle — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium-high confidence  
> **MENA targeting:** Turkey (as operating nexus), Egypt, Iraq (incl. Kurdistan Regional Government), Syria (Kurdish groups), United Arab Emirates, Jordan  
> **Sectors:** Government, Telecommunications, Internet Service Providers (ISPs), IT service providers / managed service providers, DNS registrars and registries, Media and NGOs  
> **Aliases:** Teal Kurma, Marbled Dust, SILICON, Cosmic Wolf, UNC1326, MITRE ATT&CK G1041

## Summary

Turkey-nexus, assessed to be a state-aligned espionage actor operating in support of Turkish state interests. Attribution to a Türkiye-linked actor is supported by convergence across multiple independent vendors (Cisco Talos, Hunt & Hackett, PwC, Microsoft) on victimology (Kurdish/PKK-affiliated groups, Cypriot and Greek government/telecom, Middle East and North Africa government and telecom), operational tempo aligned to Turkish geopolitical interest, and consistent DNS-hijacking tradecraft. No public sanction or indictment names a specific Turkish state entity; attribution is analytic, not adjudicated.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| DNS hijacking of core internet services (Talos) | 2017 to 2019 | Signature campaign: rather than compromising ultimate victims directly, Sea Turtle compromised third-party DNS registrars, registries and DNS providers, then altered NS and A records for targeted organizations to redirect victim traffic… | [source](https://blog.talosintelligence.com/seaturtle/) |
| Turkish espionage campaigns in the Netherlands (Hunt & Hackett) | 2021 to 2023 | Espionage operations against Dutch and European telecom, media, ISP and IT firms, and against Kurdish (PKK-affiliated) websites. Initial access in a 2023 case used a compromised-but-legitimate cPanel account. Actors deployed the custom… | [source](https://www.huntandhackett.com/blog/turkish-espionage-campaigns) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**33 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 21 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 12 hunt-lane techniques
- [`iocs/`](iocs/) — **45 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **33** across 11 tactics
- Lane split: **21 detection / 12 hunt**
- IOCs: **45**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
