# Cotton Sandstorm (G1009) — Detection & Hunt Pack

> **Attribution:** Iran-nexus — high confidence  
> **MENA targeting:** Israel, Gaza / Palestinian Territories, Iran (domestic camera enumeration / diaspora targeting), United Arab Emirates (Emirate Students Movement persona targeting)  
> **Sectors:** Elections / democratic process, News media and election-related websites, Sports / international events (2024 Paris Olympic & Paralympic Games), IPTV / streaming and broadcast providers, Commercial dynamic-display / digital-signage providers, Israeli military and defense personnel (fighter pilots, UAV operators)  
> **Aliases:** Cotton Sandstorm, Emennet Pasargad, Aria Sepehr Ayandehsazan, ASA, Marnanbridge, Haywire Kitten, Eeleyanet Gostar, Net Peygard Samavat Company

## Summary

Iranian state-sponsored cyber-enabled information-operations actor, assessed by FBI/Treasury/INCD and Microsoft to be affiliated with the Islamic Revolutionary Guard Corps (IRGC). Two Emennet Pasargad-linked Iranian nationals were previously indicted by the U.S. DOJ for the 2020 U.S.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| 2020 U.S. Presidential election voter-intimidation & false-flag disinformation (Emennet Pasargad) | 2020 | Original Emennet Pasargad hack-and-leak / cyber-enabled influence operation that sent intimidating emails to U.S. voters posing as the Proud Boys, produced a video alleging election-system vulnerabilities, and accessed election-related… | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |
| Israel hack-and-leak operations (pre-2022 PIN baseline) | 2021 – 2022 | Hack-and-leak operations against primarily Israeli organizations, combining data theft with information operations that inflict financial loss and reputational damage, using false-flag personas and exaggerated claims of access.… | [source](https://www.ic3.gov/Media/News/2022/221020.pdf) |
| Contact-HSTG / Cyber Flood hostage-family intimidation | October 2023 onward (post Oct-7) | Following the 7 October 2023 HAMAS attack, ASA used cover personas 'Cyber Flood' and 'Contact-HSTG' to send threatening SMS/messaging to family members of Israeli hostages (via https://Contact-hstg[.]com forms), posing as Al-Qassam to… | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |
| For-Humanity IPTV compromise with generative-AI news anchor | December 2023 | Under the 'For-Humanity' persona, ASA leveraged unauthorized access to a US-based IPTV streaming company to disseminate crafted Israel-Hamas-war messaging, notably incorporating a generative-AI-generated fake news anchor. Part of a… | [source](https://blogs.microsoft.com/on-the-issues/2024/10/23/as-the-u-s-election-nears-russia-iran-and-china-step-up-influence-efforts/) |
| IP-camera / RTSP surveillance harvesting | October 2023 – October 2024 | Hours after the Oct-7 attack, ASA enumerated internet-facing IP addresses running Real Time Streaming Protocol (TCP/554), primarily in Israel but also Gaza and Iran, and made harvested camera images/content available to clients via… | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |
| Cyber Court cover-hacktivist promotion network | April 2024 – September 2024 | ASA operated the online persona 'Cyber Court' (cybercourt[.]io, Telegram @cybercourt_io) to amplify the activities of several ASA-run cover-hacktivist groups — Makhlab al-Nasr, NET Hunter, Emirate Students Movement, Zeus is Talking — as… | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |
| 2024 Paris Olympics dynamic-display compromise (Regiment GUD false flag) | July 2024 | Using 'VPS-Agent' cover infrastructure, ASA compromised a French commercial dynamic-display provider to show photo montages denouncing Israeli athletes' participation in the 2024 Olympic/Paralympic Games, coupled with a fake news… | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |
| Anzu Team operation against Sweden | 2024 | Cyber-enabled information operation against Sweden conducted under the 'Anzu Team' banner, corroborated by public statements from the Swedish Security Service and Sweden's Prosecutor's Office. | [source](https://www.ic3.gov/CSA/2024/241030.pdf) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**30 techniques** across 10 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 12 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 18 hunt-lane techniques
- [`iocs/`](iocs/) — **43 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **30** across 10 tactics
- Lane split: **12 detection / 18 hunt**
- IOCs: **43**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
