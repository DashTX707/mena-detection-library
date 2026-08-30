# Pioneer Kitten — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** United Arab Emirates, Israel, Azerbaijan  
> **Sectors:** Education, Finance / financial institutions, Healthcare, Defense, Local / municipal government, Critical infrastructure  
> **Aliases:** Fox Kitten, UNC757, Parisite, RUBIDIUM, Lemon Sandstorm, Br0k3r, xplfinder

## Summary

Iran-nexus, assessed by the FBI to be a cyber actor operating with Iranian state sponsorship (Government of Iran). The group uses the Iranian company name Danesh Novin Sahand (ID 14007585836) likely as a cover IT entity. The FBI assesses a significant percentage of the group's US-focused activity is an initial-access-broker operation to enable ransomware in collaboration with affiliates (NoEscape, RansomHouse, ALPHV/BlackCat) in exchange for a percentage of ransom payments, and — separately — the group conducts computer-network-exploitation and data theft in support of the GOI against targets of Iranian state interest (US defense, Israel, Azerbaijan, UAE).

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Initial-access-broker / ransomware-enabling operations (Br0k3r / xplfinder) | 2017 to 2024 (as recently as August 2024) | High-volume network-intrusion campaign against US schools, municipal governments, financial institutions and healthcare facilities. Initial access via exploitation of internet-facing edge appliances (Citrix NetScaler CVE-2019-19781 /… | [source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a) |
| Pay2Key | Late 2020 | Hack-and-leak information operation assessed by the FBI to be aimed at undermining the security of Israel-based cyber infrastructure (not primarily for ransom). The actors operated a .onion (Tor) leak site hosted on cloud infrastructure… | [source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a) |
| Fox Kitten Campaign (ClearSky, 2020) | 2019 to 2020 | Exploitation of VPN/edge appliances (Pulse Secure CVE-2019-11510, Citrix, Fortinet, PAN-OS) to breach and persist in organizations across IT, telecom, oil & gas, aviation, government and security sectors, deploying webshells, tunneling… | [source](https://attack.mitre.org/groups/G0117/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**50 techniques** across 15 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 42 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 8 hunt-lane techniques
- [`iocs/`](iocs/) — **25 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **50** across 15 tactics
- Lane split: **42 detection / 8 hunt**
- IOCs: **25**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
