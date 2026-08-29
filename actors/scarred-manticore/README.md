# Scarred Manticore (Storm-0861) — Detection & Hunt Pack

> **Attribution:** Iran-nexus, assessed to Iran's Ministry of Intelligence and Security (MOIS) — **high confidence**
> **MENA targeting:** Saudi Arabia, UAE, Jordan, Kuwait, Oman, Iraq, Israel
> **Sectors:** Government, military, telecom, IT services, finance, NGOs
> **Aliases:** Storm-0861, DEV-0861

## Summary

Scarred Manticore is a stealthy, long-running Iran-nexus espionage actor best known for the **LIONTAIL** framework — a passive, in-memory implant that hooks the Windows HTTP stack (`HTTP.sys` / IIS) to receive commands and execute shellcode from crafted HTTP requests, leaving little on disk. It favors **web shells on internet-facing IIS/Exchange servers** for initial access and persistence, DLL side-loading, and living-off-the-land movement, targeting high-value government and telecom networks across the Gulf and Levant. Because its core tradecraft is server-side and memory-resident, this pack leans on **web-server and IIS-module telemetry** for detection and on **passive-implant / HTTP-listener hunts** for the behavior that never touches a normal process-creation log. (No official MITRE ATT&CK Group ID is assigned; mapping is derived from Check Point research.)

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| LIONTAIL framework campaign | peaked mid-2023 (pub. Oct 2023) | Passive HTTP.sys implant + web shells vs. Gulf/Levant government & telecom | [Check Point Research – Scarred Manticore](https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**28 techniques**; 20 from the tracker seed + 8 report-sourced)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (lane-colored)
- [`detections/`](detections/) — **10 Sigma rules** (IIS web-shell/module, phantom-DLL sideload, driver load, event-log tamper), all validated clean
- [`hunts/`](hunts/) — **7 hunt hypotheses** covering the 18 hunt-lane techniques; flagship = the LIONTAIL passive HTTP.sys listener (`netsh http show urlacl` + memory scanning)
- [`iocs/`](iocs/) — **18 SHA256 indicators** from the Check Point appendix (no C2 IPs/domains — expected for a passive inbound implant)
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **28** across 9 tactics
- Lane split: **10 detection / 18 hunt** — an unusually hunt-heavy pack: command-and-control is **entirely** hunt-lane (the memory-resident, log-bypassing tradecraft), while persistence is entirely detection (web shells, services)
- Detections: **10 Sigma files** · Hunts: **7** · IOCs: **18**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs enriched from the tracker seed + Check Point reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> **Notes:** No official MITRE ATT&CK Group ID exists for this actor (Storm-0861); mapping is Check Point-derived. One Stage-1 ID (`T1562.002`) was remapped to this env's canonical `T1685.001` (Disable/Modify Windows Event Log) before routing. IOCs are hashes only — the passive-listener design means there are no outbound C2 IPs/domains to collect.
