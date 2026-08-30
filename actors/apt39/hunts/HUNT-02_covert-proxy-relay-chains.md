# Hunt: APT39 covert proxy relay chains (internal pivots + external proxy egress)

- **Hypothesis:** If APT39 is routing C2 through relay infrastructure to hide the true destination, then we should see (a) *internal* hosts acting as unexpected relays — a workstation/server listening on an ad-hoc high port and forwarding traffic host-to-host in a pattern that doesn't match its role, an unexpected host-to-host relationship; and (b) *external* egress from endpoints to known anonymization/proxy/VPS endpoints (Tor, commercial proxy nets, cheap VPS ASNs) rather than to normal business destinations. The signal is the *relay topology* — a host both receiving and re-emitting a similar flow — not any single connection.
- **ATT&CK:**
  - T1090.001 — Proxy: Internal Proxy (command-and-control) — host-to-host relay inside the network
  - T1090.002 — Proxy: External Proxy (command-and-control) — egress via external proxy/anonymizer

- **Actor procedure:** APT39 chains proxies to obscure C2. Internally it uses compromised hosts (often via PLINK/SSH tunnels and simple port forwarders) to relay beacon traffic from segments that can't reach the internet directly, so only one "exit" host talks outbound. Externally it fronts C2 behind proxy/VPS infrastructure so the endpoint never contacts the real operator IP. This lets a quiet surveillance implant on a targeted user's machine reach the operator without an obvious direct connection.
- **Why a hunt, not a rule:** Proxying is ubiquitous and legitimate (corporate proxies, reverse proxies, dev tunnels, VPN clients, admin SSH forwards), so a rule on "listening port + forward" or "connection to a VPS" drowns in noise and can't be tuned per-environment without human context. The relay *topology* — same flow signature arriving at host X and leaving host X to a new hop, especially where X has no business being a proxy — requires correlating two flows and knowing the host's role. That's judgement-heavy → hunt. A confirmed unauthorized internal listener on a fixed port re-emitting to an external anonymizer (Summiting Level 3–4) can be handed to detection-engineering as a scoped rule.

## Data sources required

- Network flow / NetFlow / Zeek `conn.log` (internal east-west + egress) — bytes, duration, src/dst, ports
- Sysmon EID 3 (network connect) + EID 1 — process bound to listening/forwarding sockets (`plink`, `ssh`, `netsh portproxy`, custom forwarders)
- Firewall/proxy egress logs + threat-intel enrichment (Tor exit lists, anonymizer/VPS ASN lists)
- Host inventory / role baseline (which hosts are *supposed* to be proxies/gateways)

## Query starting point

Platform: `KQL / Microsoft Sentinel (Defender XDR)` — internal relay (flow-in ~= flow-out on a non-proxy host) + external anonymizer egress

```kusto
// (a) Internal relay: a host receiving an inbound session and re-emitting a similar-sized
//     session to a different internal/external hop within a short window (unexpected relationship)
let win = 5m;
let inbound = DeviceNetworkEvents
| where TimeGenerated > ago(7d) and ActionType == "InboundConnectionAccepted"
| project DeviceName, tIn = TimeGenerated, RemoteIP_in = RemoteIP, LocalPort;
let outbound = DeviceNetworkEvents
| where TimeGenerated > ago(7d) and ActionType == "ConnectionSuccess"
| project DeviceName, tOut = TimeGenerated, RemoteIP_out = RemoteIP, RemotePort, InitiatingProcessFileName;
inbound
| join kind=inner outbound on DeviceName
| where tOut between (tIn .. tIn + win) and RemoteIP_in != RemoteIP_out
| where InitiatingProcessFileName has_any ("plink","ssh","netsh","socat") or RemotePort in (22,443,8080,1080,9050)
| summarize relays = count(), hops = make_set(RemoteIP_out, 20) by DeviceName, InitiatingProcessFileName
| where relays >= 3                              // repeated relay behavior, not a one-off
// exclude sanctioned proxy/gateway hosts per host-role baseline (wiki)

// (b) External proxy egress: endpoints reaching Tor/anonymizer/VPS ASNs
// DeviceNetworkEvents | where RemoteIP in (TorExitList) or RemoteIPASN in (AnonymizerASNs)
//   | summarize by DeviceName, RemoteIP, RemoteIPASN | // rare on user endpoints = suspect
```

## Triage guidance

- **Likely malicious:** a user workstation or non-gateway server that both accepts an inbound session and re-emits a matching outbound session (especially via `plink`/`ssh`/`netsh portproxy`/`socat`) to a new hop; repeated relaying from a host with no proxy role; endpoint egress to Tor exit nodes or cheap-VPS/anonymizer ASNs with no business justification; a single "exit" host carrying beacons on behalf of hosts in an isolated segment.
- **Likely benign / expected:** sanctioned corporate proxies/gateways, reverse proxies and load balancers, VPN concentrators, developer SSH tunnels and CI runners, and vendor remote-access appliances legitimately relay — allowlist by host role and known port-forward configs. Admins using SSH forwards on jump boxes is expected; a marketing laptop running `netsh portproxy` is not.
- **Pivot next:** if an internal relay is confirmed, pivot to what the relayed traffic *is* (beacon periodicity, exfil volume — HUNT-04) and to the compromise of the relay host itself (creds, persistence); if external-proxy egress is confirmed, pivot the resolved/pre-proxy destination and correlate with the surveillance-suite host (HUNT-01). A confirmed operator relay inside the network is an active C2 incident → escalate to IR.

## References

- https://attack.mitre.org/groups/G0087/
- https://attack.mitre.org/techniques/T1090/001/
- https://attack.mitre.org/techniques/T1090/002/
- https://www.cisa.gov/news-events/analysis-reports/ar20-259a
