# Agrius (G1030) — Detection & Hunt Pack

> **Attribution:** Iran-nexus, destructive operator — **medium-high confidence**
> **MENA targeting:** Israel (primary), UAE
> **Sectors:** Education, technology, diamond industry, critical infrastructure
> **Aliases:** Agonizing Serpens, BlackShadow, Pink Sandstorm, DEV-0022, SharpBoys

## Summary

Agrius is an Iran-nexus **destructive** actor — the library's first wiper operator. It masquerades its operations as ransomware (Apostle, and the Deadwood/Detbosit wipers) while the true objective is data destruction and disruption, primarily against Israeli targets. Tradecraft centers on **public-facing application exploitation** for initial access (web shells such as ASPXSpy), credential theft, and the deployment of **wipers and inhibit-recovery techniques** (shadow-copy deletion, boot-configuration tampering). This pack is the first to carry meaningful **Impact-tactic** coverage — the destruction and recovery-inhibition behaviors that precede and constitute a wiper event, where fast detection and hunting genuinely change outcomes.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Apostle / Deadwood wiper-as-ransomware | 2020 – 2021 | Wiper disguised as ransomware vs. Israeli targets | [SentinelLabs – From Wiper to Ransomware](https://www.sentinelone.com/labs/from-wiper-to-ransomware-the-evolution-of-agrius/) |
| Agonizing Serpens | Jan – Oct 2023 | Wiper campaign vs. Israeli tech & higher-ed | [Unit 42 – Agonizing Serpens](https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**34 techniques**, incl. **7 Impact-tactic** — the library's first)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **18 Sigma rules** covering 20 detection-lane techniques, all validated clean (0 issues)
- [`hunts/`](hunts/) — **6 early-warning hunt hypotheses** covering the 14 hunt-lane techniques (pre-wipe staging flagship)
- [`iocs/`](iocs/) — **26 publicly-sourced indicators** (6 C2 IPs, 19 SHA256, CVE-2018-13379) from MITRE G1030 / SentinelLabs / Unit 42
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **34** across 11 tactics, including **7 Impact** (6 routed to detection)
- Lane split: **20 detection / 14 hunt** (see `intel/routing.json`)
- Detections: **18 Sigma files** · Hunts: **6** · IOCs: **26**
- Crown-jewel detections: VSS/shadow-copy deletion (T1490), raw `\\.\PhysicalDrive`/MBR write (T1561.002), data destruction (T1485), BYOVD driver load, clear-event-logs, LSASS/SAM dumping — the pre-detonation signals where speed changes outcomes.

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from MITRE G1030 + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **ATT&CK version note:** this environment's ATT&CK dataset (which the CI validator enforces, and which the rest of the repo already follows) uses `T1685` = *Disable or Modify Tools*, `T1685.005` = *Clear Windows Event Logs*, and the `stealth` tactic in place of *defense-evasion*. Technique IDs and tags conform to that dataset. IOCs shipped with the intel; no separate backfill needed.
