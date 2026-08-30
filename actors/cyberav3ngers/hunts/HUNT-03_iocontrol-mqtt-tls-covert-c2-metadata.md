# Hunt: IOCONTROL MQTT-over-TLS covert C2 — encrypted-channel metadata hunt

- **Hypothesis:** If an OT/IoT device is beaconing to IOCONTROL C2, then because the channel is MQTT wrapped in TLS (MQTTs, port 8883) the payload is opaque — but the *metadata* betrays it: an OT/IoT source (fuel controller, camera, router, PLC gateway) that has no business reaching the internet is making outbound TLS to an external broker on 8883, with a stable, low-jitter, small-message beacon rhythm and a distinctive TLS fingerprint (JA3/JA3S) and/or SNI that does not match any sanctioned vendor cloud. The embedded endpoint gives us no host telemetry, so the entire hunt lives at the network boundary / netflow tap in front of the OT segment — where the encrypted-channel technique is only visible as who-talks-to-whom, how often, and with what TLS handshake, never as content.
- **ATT&CK:**
  - T1573.002 — Encrypted Channel: Asymmetric Cryptography (command-and-control)

- **Actor procedure:** IOCONTROL uses MQTT as its dedicated C2 channel, connecting to the broker on port 8883 and wrapping the session in TLS (MQTTs). It subscribes to a `/push` topic to receive commands and publishes to `/output` and device-info topics, deliberately disguising C2 as ordinary IoT telemetry; the TLS wrap conceals command content so only destination, port, SNI/JA3 and timing are observable.
- **Why a hunt, not a rule:** TLS makes the payload uninspectable, so any detection rests on metadata that legitimately occurs — MQTTs on 8883 is normal for real IoT fleets talking to their vendor cloud, so a bare "8883 egress" rule drowns in benign telemetry in exactly the environments this actor targets. The robust discriminator is *relational and baselined*: an OT source whose expected peer set never included this broker, an SNI/JA3 that matches no sanctioned destination, and a beacon regularity distinct from human/operational traffic — a per-device egress baseline and TLS-fingerprint judgement that is analyst work, not a static signature (the C2 IP `159.100.6.69` and domain are Level-1 pivots that rotate). Once a clean allowlist of "which OT devices may speak MQTTs to which brokers" exists, a violation of it is durable enough (Level-4) to hand to detection-engineering.

## Query starting point

Platform: `Zeek/netflow (SOF-ELK / Elastic) — OT-segment TLS egress to 8883 against an egress baseline`

```elasticsearch
# (a) OT/IoT source making outbound TLS to an external broker on 8883
network.transport:tcp and destination.port:8883
  and source.ip in (OT_IOT_SEGMENT_CIDRS)
  and not destination.ip in (SANCTIONED_VENDOR_BROKER_CIDRS)   # egress allowlist
| stats sessions=count(), bytes=sum(network.bytes),
        ja3=values(tls.client.ja3), sni=values(tls.server_name),
        first=min(@timestamp), last=max(@timestamp)
   by source.ip, destination.ip, destination.as.organization
| where NOT source.ip in (baseline_devices_expected_to_use_8883)  # never-before-seen peer

# (b) beacon regularity: low-jitter cadence + small, symmetric messages
#   from the sessions above, compute inter-connection delta per (src,dst)
#   flag stddev(delta)/mean(delta) < 0.1 (metronomic) with small mean payload
#   -> automated C2 heartbeat, not human/operational traffic

# Pivot-only IOCs (do NOT anchor the hunt): dst 159.100.6.69,
#   SNI/host uuokhhfsdlk.tylarion867mino.com
```

## Data sources required

- Zeek `conn.log` + `ssl.log` (JA3/JA3S, SNI, cert) at the OT-segment egress boundary
- Netflow / IPFIX from the firewall fronting the OT/IoT network (source→dest, port, bytes, timing)
- Per-device egress baseline (which OT assets talk to which external brokers, on what cadence)
- ASN/geo enrichment on external destinations + sanctioned-vendor-broker allowlist
- Passive DNS / DoH-egress cross-reference (HUNT-05) to resolve the broker's hostname history

## Triage guidance

- **Likely malicious:** an OT/IoT device with no prior internet-broker relationship suddenly holding a persistent TLS session to an external 8883 endpoint in an unexpected ASN/country; a metronomic low-jitter beacon with small symmetric messages (heartbeat, not bulk telemetry); a JA3/SNI matching no sanctioned vendor and shared across several OT devices (fleet C2); destination overlapping known IOCONTROL infrastructure.
- **Likely benign / expected:** genuine IoT fleets speak MQTTs to their vendor cloud on 8883 as designed — allowlist those broker CIDRs/SNIs/JA3s per device class; managed cameras/routers phoning home to Hikvision/Teltonika/D-Link clouds are expected. A device on the sanctioned-broker allowlist with normal telemetry volume is not a finding.
- **Pivot next:** if a suspect broker session is confirmed, pivot to the source device for HUNT-01/HUNT-02 (persistence + shell-exec on that gateway) and to HUNT-05 to profile the broker's domain/registration. Resolve whether the device also used DoH to find the broker (detection pack T1071.004). A confirmed external C2 session from OT is an active compromise → escalate to incident-response-coordinator; if durable, hand the egress-allowlist violation to detection-engineering.

## References

- https://claroty.com/team82/research/inside-a-new-ot-iot-cyber-weapon-iocontrol
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a
- https://attack.mitre.org/techniques/T1573/002/
