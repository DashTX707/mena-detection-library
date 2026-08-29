# APT33 (G0064) — Detection & Hunt Pack

> **Attribution:** Iran-nexus — **high confidence**
> **MENA targeting:** Saudi Arabia (primary), broader Gulf
> **Sectors:** Aviation, aerospace, energy, petrochemical
> **Aliases:** HOLMIUM, Elfin, Peach Sandstorm, Refined Kitten

## Summary

APT33 is a long-running Iran-nexus actor focused on the **aviation, aerospace, and energy/petrochemical** sectors, with Saudi Arabia its primary target. It combines commodity-and-custom malware (backdoors such as TURNEDUP, and droppers/loaders like DarkComet, NanoCore, PoshC2, POWERTON) with **spear-phishing using industry-themed job-recruitment lures**, aggressive **password spraying** against cloud/on-prem identity, and living-off-the-land tooling. It is also assessed to be linked to **Shamoon** destructive/disk-wiper operations, giving this pack a credential-access + Impact edge alongside the phishing intrusion chain. Detection leans on identity (password-spray/spraying analytics), email lures, and endpoint execution; hunts cover the infrastructure and lower-telemetry tradecraft.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Spear-phishing vs. Saudi/US aviation | 2016–2017 | Recruitment-themed lures vs. aviation/defense | [Mandiant – APT33](https://cloud.google.com/blog/topics/threat-intelligence/apt33-insights-into-iranian-cyber-espionage/) |
| Petrochemical targeting in Saudi Arabia | 2017–2018 | Energy/petrochemical intrusions | [Mandiant – APT33](https://cloud.google.com/blog/topics/threat-intelligence/apt33-insights-into-iranian-cyber-espionage/) |
| Suspected Shamoon linkage | 2016–2018 | Destructive disk-wiper operations | [Mandiant – APT33](https://cloud.google.com/blog/topics/threat-intelligence/apt33-insights-into-iranian-cyber-espionage/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**48 techniques** across 14 tactics — 31 G0064 base + 17 additions incl. the Peach Sandstorm cloud/identity set)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **26 Sigma rules** covering all 37 detection-lane techniques (merged), all validated clean
- [`hunts/`](hunts/) — **6 hunt hypotheses** covering the 11 hunt-lane techniques (Golden-SAML flagship + Shamoon disk-wipe precursor early-warning)
- [`iocs/`](iocs/) — **8 publicly-sourced indicators** (4 Peach Sandstorm IPs, 3 masquerading domains, CVE-2017-11774)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **48** across 14 tactics
- Lane split: **37 detection / 11 hunt** — strong identity detection (password-spray + the `go-http-client`/TOR-ASN Peach Sandstorm sign-in signal), phishing, credential access; hunt lane holds Golden SAML, covert tunneling, and the Shamoon wipe (visible only post-impact → hunt the precursor)
- Detections: **26 Sigma files** (merged from 37 techniques) · Hunts: **6** · IOCs: **8**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from MITRE G0064 + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** all 48 IDs verified against the CI's bundled ATT&CK dataset on the first pass (Shamoon Impair-Defenses uses this env's `T1685`/`T1685.005` under `defense-impairment`; defense-evasion tagged `attack.stealth`). The Shamoon destructive set is caveated in the intel as *assessed* APT33-nexus, not a hard MITRE G0064 mapping.
