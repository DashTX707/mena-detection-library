# Cadelle — ATT&CK Technique Mapping

> Attribution: Iran-nexus — low-medium confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **8** across **3** tactics.

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Input Capture: Keylogging | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Backdoor.Cadelspy logs keystrokes on the compromised host, capturing typed credentials, messages, and other user input as part of its broad surveillance of the target's communications and activity. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Application Window Discovery | [T1010](https://attack.mitre.org/techniques/T1010/) | Cadelspy collects the titles of open application windows on the infected host, giving the operators context on which applications the victim is using and the content of active windows. |
| Peripheral Device Discovery | [T1120](https://attack.mitre.org/techniques/T1120/) | Cadelspy monitors the infected computer for the insertion of USB/removable storage devices and extracts printer information, enabling it to intercept and steal documents the victim sends to the printer as well as data from attached peripherals. |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | Cadelspy gathers system information from the compromised host (host/system details) to profile the victim environment for its operators. |

## Collection

| Technique | ID | Notes |
|---|---|---|
| Clipboard Data | [T1115](https://attack.mitre.org/techniques/T1115/) | Cadelspy steals the contents of the Windows clipboard on infected systems, capturing copied text such as passwords, URLs, and message fragments. |
| Screen Capture | [T1113](https://attack.mitre.org/techniques/T1113/) | Cadelspy captures screenshots of the victim's desktop and also takes photos via the computer's webcam, providing visual surveillance of the user and their on-screen activity. |
| Audio Capture | [T1123](https://attack.mitre.org/techniques/T1123/) | Cadelspy records audio from the compromised system's microphone to eavesdrop on the victim's environment and conversations. |
| Archive Collected Data | [T1560](https://attack.mitre.org/techniques/T1560/) | Before exfiltration, Cadelspy compresses the stolen data (keystrokes, screenshots, audio, documents, clipboard contents) into .cab archive files on the host. |
