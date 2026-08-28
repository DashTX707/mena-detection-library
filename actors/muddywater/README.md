# MuddyWater (G0069) — Detection & Hunt Pack

> **Attribution:** Iran-nexus, assessed to Iran's Ministry of Intelligence and Security (MOIS) — **high confidence**
> **MENA targeting:** UAE, Saudi Arabia, Israel, Turkey, Iraq, Jordan, Egypt
> **Sectors:** Telecom, government (esp. local), finance, defense, oil & gas, energy, marine services
> **Aliases:** Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, MuddyKrill

## Summary

MuddyWater is one of the most persistent Iran-nexus espionage actors operating against MENA organizations. It is characterized by heavy use of **living-off-the-land** tradecraft (PowerShell, scheduled tasks, WMI), **legitimate remote-management tooling** (RMM abuse) for hands-on-keyboard access, custom C2 (POWERSTATS / MuddyC2 family, PowGoop loader), and commodity credential-theft tooling (Mimikatz, procdump). Its reliance on native binaries and signed RMM software is exactly why this pack splits coverage between **Sigma detections** (for the concrete, low-false-positive behaviors) and **hunts** (for the LOLBIN/RMM activity that needs environmental baselining).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| CISA/FBI/NSA joint advisory AA22-055A | Feb 2022 | Detailed MuddyWater TTPs and MOIS attribution | [CISA AA22-055A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a) |
| MuddyViper backdoor campaign | Sep 2024 – Mar 2025 | Targeted Israeli **and Egyptian** organizations | Tracker: iran-apt |
| "Operation Olalampo" | first observed Jan 2026 | Campaign vs. MENA orgs | [Group-IB](https://www.group-ib.com/blog/muddywater-operation-olalampo/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes on each entry._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**68 techniques / 17 tactics**, sourced to MITRE G0069)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap
- [`detections/`](detections/) — **32 Sigma rules**, all validated clean with `sigma-cli` 3.1.0 (0 errors)
- [`hunts/`](hunts/) — **14 consolidated hunt hypotheses** covering the 35 hunt-lane techniques
- [`iocs/`](iocs/) — publicly-sourced indicators (5; conservative — no hashes/IPs until the CISA AA22-055A appendix is ingested manually)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **68** across 17 tactics
- Lane split: **33 detection / 35 hunt** (see `intel/routing.json`)
- Detections: **32 Sigma files** · Hunts: **14** · IOCs: **5**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (extract TTPs from MITRE G0069 + CISA AA22-055A + tracker) → `decision-agent` (route detect vs. hunt) → `detection-engineer` (Sigma) + `threat-hunter` (hunts).

> **Note:** the Stage-2 `routing.json` was reconstructed from the shipped detection rules after the decision-agent's write did not persist, so the lane split reflects exactly what ships. IOCs are deliberately minimal because the CISA advisory blocked automated fetch (HTTP 403) — its indicator appendix should be added manually.
