# Predatory Sparrow — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Iran, Syria (Indra-linked precursor wiper activity)  
> **Sectors:** Metals / steel manufacturing (OT/ICS), Oil & gas / fuel distribution (fuel-pump control systems), Transportation / railway, Financial services / banking, Cryptocurrency exchange, Critical infrastructure / OT-ICS  
> **Aliases:** Gonjeshke Darande, Indra (linked/overlapping cluster), MeteorExpress (campaign/tooling name)

## Summary

Anti-Iran destructive/OT actor operating publicly under the Persian-language persona 'Gonjeshke Darande' (Predatory Sparrow). The persona self-presents as anti-regime hacktivists, but the operational sophistication (validated OT/ICS access sufficient to cause a physical molten-metal spill at a steel plant, multi-stage wiper toolchains, and deconfliction/'safety' messaging) is widely assessed in journalistic and analyst reporting to indicate a state or state-directed actor, most commonly attributed to Israel. Public attribution is largely journalistic (e.g., anonymous US/Israeli official sourcing to the New York Times on the October 2021 fuel-system attack) plus the group's own self-claims on Telegram; there is no government advisory formally attributing the group.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Iranian Railways wiper & defacement (MeteorExpress) | 2021-07-09 | Multi-component destructive attack against the Islamic Republic of Iran Railways and the Ministry of Roads & Urban Development. A batch-script toolchain deployed via Active Directory Group Policy dropped the Meteor wiper… | [source](https://www.sentinelone.com/labs/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/) |
| Iranian fuel-station payment-system disruption (October 2021) | 2021-10-26 | Nationwide disruption of Iran's subsidised-fuel card payment network; the majority of gas stations could not process government fuel-subsidy cards. The actor reportedly reached the stations by compromising a central… | [source](https://time.com/6548680/iran-hacker-gas-station-cyberattack-israel/) |
| Iranian steel plants OT sabotage (Khuzestan / Mobarakeh / Hormozgan) | 2022-06-27 | Compromise of industrial control systems at three of Iran's largest steel producers. At Khuzestan Steel Company the actor manipulated the production-control plane and caused an overhead crane/ladle to spill molten metal onto the factory… | [source](https://www.picussecurity.com/resource/blog/predatory-sparrow-inside-the-cyber-warfare-targeting-irans-critical-infrastructure) |
| Iranian fuel-station disruption (December 2023) | 2023-12-18 | Repeat disruption of Iran's fuel distribution, with Iran's oil minister confirming a cyberattack that took roughly 70% of the country's fuel stations offline and forced many to operate manually. The actor again claimed responsibility on… | [source](https://www.cnbc.com/2023/12/18/pro-israel-hackers-claim-cyberattack-disrupting-irans-gas-stations.html) |
| Bank Sepah data destruction & Nobitex crypto burn (June 2025) | 2025-06-17 | Amid the June 2025 Israel-Iran conflict, the actor claimed a destructive attack on state-owned Bank Sepah (asserting the bank funded the Iranian military and destroying banking data), and the following day drained/burned roughly $90M… | [source](https://en.wikipedia.org/wiki/Predatory_Sparrow) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**34 techniques** across 12 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 26 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **5 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **34** across 12 tactics
- Lane split: **26 detection / 8 hunt**
- IOCs: **5**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
