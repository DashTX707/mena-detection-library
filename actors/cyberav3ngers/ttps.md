# CyberAv3ngers — ATT&CK Technique Mapping

> Attribution: Iran-nexus — high confidence.
> Enriched from public threat reporting (per-technique sources in intel/cti-pipeline.json).

Total techniques mapped: **20** across **9** tactics.

## Resource Development

| Technique | ID | Notes |
|---|---|---|
| Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | CyberAv3ngers developed IOCONTROL (aka OrpaCrypt), a bespoke modular Linux malware platform purpose-built to run across heterogeneous IoT/OT devices (IP cameras, routers, PLCs, HMIs, firewalls, fuel systems) from many vendors, plus custom empty ladder-logic files tailored per Unitronics device model. |
| Acquire Infrastructure: Domains | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | The actors registered the domain tylarion867mino.com on 2023-11-23 (WHOIS) and used the subdomain uuokhhfsdlk.tylarion867mino.com as the IOCONTROL command-and-control hostname to manage compromised devices. |

## Initial Access

| Technique | ID | Notes |
|---|---|---|
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | The actors gained access to internet-exposed Unitronics Vision Series PLCs/HMIs reachable on the default TCP port 20256. The devices were internet-facing with default or no credentials, and were compromised at scale (at least 75 devices across four assessed waves, >=34 in the U.S. WWS Sector). This is the primary DETECTABLE initial-access surface for this OT actor. |
| External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | The actors abused the internet-exposed remote-programming interface of Unitronics PLC/HMI devices (remote logic upload/download over TCP 20256) as an external remote service to reach and reprogram OT devices directly from the internet. |
| Valid Accounts: Default Accounts | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | The actors authenticated to internet-connected Unitronics devices using the vendor default password (widely reported as '1111') or no password at all, gaining privileged control of the PLC/HMI. Default-credential access is a core DETECTABLE behavior for this actor. |

## Execution

| Technique | ID | Notes |
|---|---|---|
| Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | IOCONTROL exposes an 'Execute command' module that runs arbitrary OS commands on the compromised Linux IoT/OT device via a system() call and publishes the output back to C2; its persistence backdoor is itself a bash rc script. |

## Persistence

| Technique | ID | Notes |
|---|---|---|
| Boot or Logon Initialization Scripts: RC Scripts | [T1037.004](https://attack.mitre.org/techniques/T1037/004/) | IOCONTROL installs a backdoor as an rc3.d boot script at /etc/rc3.d/S93InitSystemd.sh; the script runs a watchdog loop that relaunches /usr/bin/iocontrol every 5 seconds if not running, ensuring persistence across device reboots. |

## Defense Evasion

| Technique | ID | Notes |
|---|---|---|
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | IOCONTROL blends in by naming its main binary 'iocontrol' under /usr/bin and its persistence boot script 'S93InitSystemd.sh' to mimic a legitimate systemd initialization component on the Linux device. |
| Obfuscated Files or Information: Encrypted/Encoded File | [T1027.013](https://attack.mitre.org/techniques/T1027/013/) | IOCONTROL stores its configuration entries (including the C2 hostname, port, and MQTT topics) as AES-256-CBC encrypted blobs on disk; each entry is length-prefixed and decrypted at runtime, hiding C2 and operational parameters from static inspection. |
| Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) | At runtime IOCONTROL derives the AES key/IV (the SHA-256 of an embedded victim GUID, used as a hex string) from environment variables and decrypts each stored configuration entry immediately before use to obtain its C2 hostname, port and MQTT topics. |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | IOCONTROL's 'Self-delete' module stops execution and removes the malware main binary, its persistence service (the rc3.d boot script) and related log files to erase its footprint on the device, then reports completion to C2. |

## Credential Access

| Technique | ID | Notes |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | CISA maps the actors' authentication to internet-connected Unitronics devices on default TCP port 20256 to Brute Force — repeated/automated login attempts against devices to obtain valid (often default) credentials. |

## Discovery

| Technique | ID | Notes |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | IOCONTROL includes a 'Port scan' module: given a start IP, end IP and a target port, it scans the range and publishes results to C2 — enabling the operators to enumerate additional reachable services and devices from a compromised OT foothold. |

## Command and Control

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) | IOCONTROL uses the MQTT IoT messaging protocol as its dedicated C2 channel (connecting to the broker on port 8883), subscribing to a '/push' topic to receive commands and publishing to '/output' and device-info topics — deliberately disguising C2 as ordinary IoT telemetry traffic. |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Before connecting to C2, IOCONTROL resolves its C2 hostname (uuokhhfsdlk.tylarion867mino.com) using Cloudflare DNS-over-HTTPS (1.1.1.1, 'application/dns-json' requests) instead of the device's normal resolver, to evade DNS monitoring; the DoH response returned the C2 IP 159.100.6.69. |
| Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | IOCONTROL wraps its MQTT C2 in TLS (MQTTs on port 8883), using transport encryption to conceal the content of command-and-control exchanges with the attacker infrastructure. |

## Impact

| Technique | ID | Notes |
|---|---|---|
| Data Manipulation: Stored Data Manipulation | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | On compromised Unitronics PLCs the actors erased the original ladder-logic file and downloaded their own logic containing no inputs or outputs, halting the device's intended control function, and set the ladder-logic software version to an older version so operators' engineering workstations could no longer communicate with the PLC (recoverable only by matching the workstation version or factory reset). The actors also did not burn their logic to the device, preventing retrieval of the original logic. [ICS effect; expressed via Enterprise T1565.001] |
| Account Access Removal | [T1531](https://attack.mitre.org/techniques/T1531/) | The actors renamed the compromised PLC/HMI devices (the device name is a required field for remote connections, so renaming delayed/blocked operator remote access) and enabled password protection on the upload/settings functions to prevent operators from remotely changing the programming and removing the defacement. [ICS effect; expressed via Enterprise T1531] |
| Endpoint Denial of Service | [T1499](https://attack.mitre.org/techniques/T1499/) | The actors disabled the upload and download functions of the PLC to stop operators from taking down the defacement splash page, and changed the device's default remote-communication port from 20256 to 20257 — denying legitimate remote operation of the endpoint. [ICS effect; expressed via Enterprise T1499] |
| Defacement: Internal Defacement | [T1491.001](https://attack.mitre.org/techniques/T1491/001/) | The actors uploaded a splash page to the HMI screen displaying 'You have been hacked, down with Israel. Every equipment made in Israel is CyberAv3ngers legal target,' overwriting the normal operational display (input/output readings); on older devices unable to render a graphic they displayed a text file with the same message. This is the actor's signature, highly DETECTABLE impact behavior. [ICS/HMI defacement; expressed via Enterprise T1491.001] |
