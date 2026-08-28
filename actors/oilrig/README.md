# OilRig (G0049 / APT34) — Detection & Hunt Pack

> **Attribution:** Iran-nexus, assessed to Iran's Ministry of Intelligence and Security (MOIS) — **high confidence**
> **MENA targeting:** Saudi Arabia, UAE, Iraq, Jordan, Israel, Kuwait, Qatar
> **Sectors:** Government, financial, energy, chemical, telecom
> **Aliases:** COBALT GYPSY, Helix Kitten, Evasive Serpens, Hazel Sandstorm, EUROPIUM, ITG13, Earth Simnavaz, Crambus, TA452

## Summary

OilRig is a long-running Iran-nexus espionage group that has targeted Gulf government, energy, and telecom organizations for a decade. Its tradecraft centers on **credential theft against Exchange/webmail**, **DNS-tunneling and HTTP C2** (custom backdoors such as Helminth, QUADAGENT, TwoFace webshell, Veaty/Spearal), abuse of **legitimate services for exfiltration**, and living-off-the-land discovery. The DNS-tunneling and webshell tradecraft is exactly why this pack splits between crisp endpoint/webshell **Sigma detections** and **hunts** for the network-side and baselining-dependent behavior.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Iraqi government intrusion (Veaty / Spearal backdoors) | Sep 2024 | DNS-tunneling + email-based C2 vs. Iraqi government | Check Point Research (verify exact URL before external citation) |
| Earth Simnavaz Exchange credential theft | 2024 | Exploited CVE-2024-30088; credential theft via Exchange | [Trend Micro – Earth Simnavaz](https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**87 techniques**: 82 Enterprise + 5 ICS, sourced to MITRE G0049)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored; ICS omitted from the enterprise layer)
- [`detections/`](detections/) — **29 Sigma rules** covering 40 detection-lane techniques, all validated clean with `sigma-cli` (0 issues)
- [`hunts/`](hunts/) — **12 consolidated hunt hypotheses** covering the 47 hunt-lane techniques
- [`iocs/`](iocs/) — **17 publicly-sourced indicators** ingested from the Trend Micro Earth Simnavaz report (16 SHA256 sample hashes + CVE-2024-30088)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **87** (82 Enterprise + 5 ICS)
- Lane split: **40 detection / 47 hunt** (see `intel/routing.json`)
- Detections: **29 Sigma files** · Hunts: **12** · IOCs: **17** (Trend Micro Earth Simnavaz appendix)

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** ICS technique tags (T0853/T0865) are carried in filenames/descriptions rather than `attack.*` tags, because pySigma's validator only recognizes Enterprise IDs — ICS coverage is documented, not tag-asserted. `routing.json` is authored by the read-only decision-agent and persisted by the orchestrator. IOCs were backfilled from the Trend Micro Earth Simnavaz report (fetched via a browser user-agent after the default fetch was WAF-blocked); Trend Micro publishes no C2 IPs/domains in the article body, so this set is the sample-hash appendix plus the exploited CVE.
