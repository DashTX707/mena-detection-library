# Infy — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Iran (domestic dissidents and civil society), Middle Eastern governments and embassies  
> **Sectors:** Government, Diplomatic / embassies, Dissidents, activists and expatriates, Media and Persian-language press, Civil society / political organizations  
> **Aliases:** Prince of Persia, Operation Mermaid, Foudre (malware family alias), Tonnerre (malware family alias)

## Summary

Iran-nexus, assessed medium confidence. One of the longest-running Iranian cyber-espionage operations, with activity dating to ~2007. Unit 42 tied the C2 registration infrastructure to an Iranian individual ('Amin Jalali', Tehran contact details and yahoo.com registrant email) and to Iranian hosting/telecom infrastructure, and the operation's exclusive focus on surveillance of Iranian dissidents, expatriates, Persian-language media, and Middle Eastern/European governments and embassies is consistent with Iranian state intelligence interests.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Infy — decade of targeted attacks (Prince of Persia) | 2007 to 2016 | Long-running espionage campaign using the proprietary Infy backdoor (and 'Infy M' variant) delivered via spear-phishing emails carrying weaponized Word/PowerPoint documents and multi-layer self-extracting archives. Backdoor established… | [source](https://unit42.paloaltonetworks.com/prince-of-persia-infy-malware-active-in-decade-of-targeted-attacks/) |
| Infy returns as Foudre (Ride the Lightning) | 2017 | After the 2016 sinkhole, the operator returned with a rebuilt toolset dubbed Foudre ('lightning'). A self-executable spear-phishing attachment drops a loader, malicious DLL and decoy file to %ALLUSERSPROFILE%\AppData\SnailDriver V<ver>,… | [source](https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/) |
| Tonnerre second-stage implant (After Lightning Comes Thunder) | 2018 to 2021 | Foudre-delivered second-stage backdoor 'Tonnerre' ('thunder'). Delivered via macro-enabled Word documents (lures included a photo of Dorud city governor Mojtaba Biranvand and ISAAR-themed content); on document close a macro drops… | [source](https://research.checkpoint.com/2021/after-lightning-comes-thunder/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**37 techniques** across 10 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 27 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 10 hunt-lane techniques
- [`iocs/`](iocs/) — **70 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **37** across 10 tactics
- Lane split: **27 detection / 10 hunt**
- IOCs: **70**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
