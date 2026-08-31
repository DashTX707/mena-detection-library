# Domestic Kitten — Detection & Hunt Pack

> **Attribution:** Iran-nexus — medium confidence  
> **MENA targeting:** Iran, Iraq (Kurdistan region / Kurdish targets), Turkey (diaspora/dissident targets)  
> **Sectors:** Individuals / dissidents and government opposition, Ethnic and religious minorities (Kurds, Sunni minorities), Journalists and activists, ISIS supporters and perceived internal-security threats, Civil society  
> **Aliases:** Domestic Kitten, APT-C-50

## Summary

Iran-nexus. Check Point Research attributes Domestic Kitten / APT-C-50 to the Iranian government based on the exclusively domestic-repression targeting set (Iranian dissidents, Kurds, ISIS supporters, and ethnic/religious minorities such as the Mujahedin-e Khalq and the Azerbaijan National Resistance Organization), the Persian-language decoys and infrastructure, Iranian operator IP addresses geolocated to Tehran and Karaj, and Iranian WHOIS registrants (registrant handle 'nobody.gu3st' active on Iranian hacking forums for the linked Rampant Kitten infrastructure). The operation has run since ~2016 across at least 10 mobile campaigns plus a parallel Windows/Android desktop-and-phone espionage effort.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| Domestic Kitten mobile surveillance operation (10+ FurBall campaigns) | 2016 to 2021 | Long-running Android surveillance operation delivering the FurBall spyware (a trojanized/customized derivative of the commercial KidLogger parental-control app) via decoy apps impersonating a fake VIPRE mobile security product, the ISIS… | [source](https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/) |
| FurBall fake-VPN / fake translation-service campaign (ESET) | 2021 to 2022 | A slimmed FurBall variant distributed from a copycat website (downloadmaghaleh.com) impersonating a legitimate Persian scientific-paper translation service; the malicious APK (com.getdoc.freepaaper.dissertation) was masked behind Google… | [source](https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/) |
| Rampant Kitten desktop-and-mobile espionage campaign | 2014 to 2020 | Parallel effort against the same domestic/dissident target set using four Windows infostealer families (TelB, TelAndExt, a Python PyInstaller stealer, and HookInjEx) that steal Telegram Desktop data, KeePass databases, documents, and… | [source](https://research.checkpoint.com/2020/rampant-kitten-an-iranian-espionage-campaign/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**28 techniques** across 10 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 12 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 16 hunt-lane techniques
- [`iocs/`](iocs/) — **65 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **28** across 10 tactics
- Lane split: **12 detection / 16 hunt**
- IOCs: **65**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
