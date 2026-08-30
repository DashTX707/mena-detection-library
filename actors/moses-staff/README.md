# Moses Staff — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Israel, Saudi Arabia (via Abraham's Ax persona)  
> **Sectors:** Critical infrastructure, Engineering / construction, Finance, Government, Utilities / energy, Manufacturing  
> **Aliases:** Moses Staff, MosesStaff, Cobalt Sapling, DEV-0500

## Summary

Iran-nexus, ideologically motivated anti-Israel actor active since at least September 2021, conducting hack-and-leak plus destructive operations. Not financially motivated: encryption is used to destroy and disrupt — no ransom demand is made and no decryption is offered, and the encryption scheme was found by Check Point to be recoverable in some cases only due to implementation flaws, not by design. The related 'Abraham's Ax' persona (targeting Saudi/regional government) is tracked to the same Cobalt Sapling cluster.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| MosesStaff hack-and-leak / destructive encryption of Israeli companies | 2021 (public from September 2021, reported 2021-11) | Moses Staff breached Israeli organizations by exploiting known vulnerabilities in public-facing infrastructure (notably Microsoft Exchange — ProxyLogon/ProxyShell), dropped ASPX web shells (e.g. IISpool.aspx under… | [source](https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/) |
| StrifeWater RAT earlier-stage access campaign | 2021 to 2022 (reported 2022-02) | Cybereason uncovered a previously undocumented remote-access trojan, StrifeWater, used by Moses Staff in earlier compromise stages for reconnaissance, command execution, screenshots and module downloading. StrifeWater masqueraded as the… | [source](https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**28 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 14 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 14 hunt-lane techniques
- [`iocs/`](iocs/) — **23 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **28** across 11 tactics
- Lane split: **14 detection / 14 hunt**
- IOCs: **23**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
