# Greenbug — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Saudi Arabia, Iran, Iraq, Bahrain, Qatar, Kuwait  
> **Sectors:** Government, Telecommunications, Aviation, Energy / oil & gas, Investment / financial, Education  
> **Aliases:** Greenbug, ISMDOOR group (named after primary backdoor), public MITRE ATT&CK Group G0049 (Greenbug)

## Summary

Iran-nexus cyber-espionage. Symantec assesses Greenbug operates in support of Iranian state interests, based on Middle East/Gulf targeting aligned with those interests, use of an Iran-nexus toolset (ISMDOOR/ISMAgent/ISMInjector, Nidiran), and temporal/host overlap with the destructive Shamoon 2 (W32.Disttrack.B) campaigns against Saudi organizations. Symantec detected an ISMDOOR infection on an administrator computer at an organization later hit with Disttrack, and assesses Greenbug MAY have supplied the credentials that Shamoon used to spread — i.e.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| ISMDOOR espionage / Shamoon 2 credential-theft precursor | 2016 to early 2017 | Greenbug used fake business-proposal spearphishing emails to deliver the Trojan.Ismdoor (ISMDOOR) PowerShell-based backdoor to aviation, investment, government and education organizations across Saudi Arabia, Iran, Iraq, Bahrain, Qatar,… | [source](https://www.security.com/threat-intelligence/shamoon-attacks-mount-middle-east) |
| ISMAgent / ISMInjector — UAE government | 2017-08 | Continued development of the toolset: an attack on a United Arab Emirates government target used ISMAgent (a successor backdoor to ISMDOOR) delivered via ISMInjector, a Trojan that injects ISMAgent into legitimate processes.… | [source](https://www.security.com/threat-intelligence/greenbug-espionage-telco-south-asia) |
| DNS-based ISMDOOR command-and-control shift | 2017 | NETSCOUT ASERT documented Greenbug moving ISMDOOR away from HTTP C2 toward a DNS-based covert channel — using DNS queries (with AAAA/IPv6 responses) and a modified-base64 encoding to build a bidirectional command-and-control channel… | [source](https://www.netscout.com/blog/asert/greenbugs-dns-isms) |
| South Asia telecom espionage | 2019-04 to 2020-04 | Greenbug targeted at least three telecom operators in Pakistan (South Asia), relying on off-the-shelf tools and living-off-the-land techniques for persistent, low-profile credential theft. Initial access via a CHM file… | [source](https://www.security.com/threat-intelligence/greenbug-espionage-telco-south-asia) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**35 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 33 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 2 hunt-lane techniques
- [`iocs/`](iocs/) — **38 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **35** across 11 tactics
- Lane split: **33 detection / 2 hunt**
- IOCs: **38**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
