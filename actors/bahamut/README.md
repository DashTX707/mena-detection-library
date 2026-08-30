# Bahamut — Detection & Hunt Pack

> **Attribution:** Iran-nexus — low confidence  
> **MENA targeting:** United Arab Emirates, Saudi Arabia, Qatar, Egypt, Iran, Palestine  
> **Sectors:** Government officials and diplomats, Military / defense personnel, Human-rights activists and NGOs, Journalists and media, Islamic scholars / religious and separatist activists (incl. Sikh-rights and Kashmir advocates), Business executives and industry figures  
> **Aliases:** Bahamut, Windshift (MITRE ATT&CK G0112, clustered), EHDevel (historical linkage)

## Summary

Mercenary 'hack-for-hire' / cyber-espionage-for-hire operation active since at least 2016-2017. Bahamut is best understood as a service provider that runs espionage and disinformation operations on behalf of multiple, likely-changing paying clients, rather than a single-sponsor state APT. This mixed victimology (across rival Middle East and South Asia states and causes) is a core reason attribution to any one government sponsor is unresolved.

## Key campaigns (MENA-relevant)

| Campaign | Date | Summary | Source |
|---|---|---|---|
| BlackBerry unmasking — phishing, fake news, and fake apps | 2020-10 (activity from ~2016 onward) | BlackBerry documented Bahamut as a prolific hack-for-hire group running highly targeted credential-phishing and account-takeover operations backed by a vast network of fake news websites, social-media personas, and single-use,… | [source](https://blogs.blackberry.com/en/2020/10/blackberry-uncovers-massive-hack-for-hire-group-targeting-governments-businesses-human-rights-groups-and-influential-individuals) |
| SecureVPN — fake VPN Android spyware | 2022 (ESET disclosed 2022-11) | Bahamut distributed trojanized versions of the legitimate SoftVPN and OpenVPN Android apps (packages com.secure.vpn and com.openvpn.secure) via a fake distribution site, thesecurevpn[.]com, mimicking the real SecureVPN service. At least… | [source](https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/) |
| SafeChat / CoverIm (CoverLM) — WhatsApp spear-message spyware | 2023 (CYFIRMA) | Bahamut delivered a fake Android chat app 'SafeChat' (Safe_Chat.apk, malware family CoverIm/CoverLM) to individuals in South Asia via WhatsApp spear-messaging. The app repeatedly prompted for Accessibility Services and… | [source](https://www.cyfirma.com/research/apt-bahamut-targets-individuals-with-android-malware-using-spear-messaging/) |
| Original discovery — Middle East cyber-espionage | 2017-06 (Bellingcat) | Bellingcat first exposed Bahamut as a hack-for-hire operation targeting government officials, human-rights groups and other high-profile entities across South Asia and the Middle East using malicious Android and iOS apps for… | [source](https://www.bellingcat.com/news/mena/2017/06/12/bahamut-pursuing-cyber-espionage-actor-middle-east/) |

_See the [MENA Threat Actor Tracker](https://github.com/DashTX707/MENA-Threat-Actor-Tracker) for full sourcing and confidence notes._

## What's in this pack

- [`ttps.md`](ttps.md) — full ATT&CK technique mapping (**41 techniques** across 11 tactics)
- [`navigator-layer.json`](navigator-layer.json) — ATT&CK Navigator heatmap (red=detection, orange=hunt)
- [`detections/`](detections/) — Sigma rules covering the 11 detection-lane techniques, validated clean
- [`hunts/`](hunts/) — hunt hypotheses covering the 30 hunt-lane techniques
- [`iocs/`](iocs/) — **16 publicly-sourced indicators**
- [`intel/`](intel/) — pipeline provenance (`cti-pipeline.json`, `routing.json`)

## Coverage snapshot

- TTPs mapped: **41** across 11 tactics
- Lane split: **11 detection / 30 hunt**
- IOCs: **16**

## Provenance

Produced via the mena-detection-library pipeline:
`cti-expert` (TTPs from MITRE + public reporting) → `decision-agent` → `detection-engineer` + `threat-hunter`.

> All technique IDs verified against the CI's bundled ATT&CK dataset (this env uses `T1685.x` for the Impair-Defenses family and the `stealth` tactic for defense-evasion).
