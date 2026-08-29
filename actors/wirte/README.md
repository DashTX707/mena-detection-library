# WIRTE (G0090) — Detection & Hunt Pack

> **Attribution:** Palestinian-nexus, assessed Hamas-affiliated; some vendors link it as a Gaza Cybergang subgroup (Securelist rates that linkage *low confidence*) — **medium confidence overall**
> **MENA targeting:** Palestinian Authority, Jordan, Iraq, Egypt, Saudi Arabia (Check Point victim list); Lebanon, Syria, Turkey, Armenia, Cyprus (Securelist campaign list); Israel (disruptive ops)
> **Sectors:** Diplomatic, financial, military, legal, technology, government
> **Aliases:** Ashen Lepus

## Summary

WIRTE is a Palestinian-nexus actor known for **living-off-the-land** operations running since at least 2019, and — more recently — a shift into **disruptive/destructive** activity. Its espionage tradecraft centers on malicious Office documents with VBA macros, PowerShell/VBScript staging, and LOLBIN execution; in 2024 it deployed the **SameCoin wiper** against Israeli targets. This pack therefore spans both the stealthy LotL intrusion chain (detection + hunt) and a slice of **Impact**-tactic destructive coverage, making WIRTE a useful bridge between the espionage-focused Gaza Cybergang pack and the wiper-focused Agrius pack.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Living-off-the-land espionage | since 2019 (pub. Aug 2021) | LotL intrusion set across the Middle East | [Securelist – WIRTE's campaign](https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044/) |
| SameCoin wiper (disruptive) | Feb & Oct 2024 | Destructive activity vs. Israel | [Check Point – WIRTE expands to disruptive activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**39 techniques** across 11 tactics, incl. **2 Impact** — the SameCoin wiper)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **13 Sigma rules** covering the 13 detection-lane techniques, all validated clean (0 issues)
- [`hunts/`](hunts/) — **9 consolidated hunt hypotheses** covering the 26 hunt-lane techniques (COM-hijack flagship; `oref.org.il` geo-gate early-warning for the wiper)
- [`iocs/`](iocs/) — **51 publicly-sourced indicators** (14 IPs, 21 domains, 16 hashes) from Securelist + Check Point (network indicators defanged; `oref.org.il` deliberately excluded as a legitimately-abused site)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **39** across 11 tactics, including **2 Impact** (SameCoin: T1485 data destruction, T1491.001 internal defacement — both routed to detection)
- Lane split: **13 detection / 26 hunt** (see `intel/routing.json`)
- Detections: **13 Sigma files** · Hunts: **9** · IOCs: **51**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from MITRE G0090 + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** all 39 technique IDs were verified against the CI's bundled ATT&CK dataset before routing (no ID corrections needed). The heavy hunt lane (26/39) reflects WIRTE's living-off-the-land style — much of its tradecraft is high-base-rate LOLBIN/obfuscation activity that needs baselining rather than crisp rules. IOCs shipped with the intel.
