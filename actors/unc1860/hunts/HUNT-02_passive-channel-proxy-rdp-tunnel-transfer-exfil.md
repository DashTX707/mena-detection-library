# Hunt: UNC1860 passive-channel proxy, TUNNELBOI RDP tunneling, and inbound file transfer / collection / exfil — internal connections sourced from a compromised web/edge server

- **Hypothesis:** If UNC1860 is using a compromised internet-facing server as its passive foothold, then — because everything rides the server's *own* inbound web channel rather than a new outbound C2 — the pivot/movement/exfil evidence is an *unexpected relationship*: a web/edge server that normally only *serves* clients suddenly **originating** internal connections (TEMPLEPLAY HTTP proxy to otherwise-unreachable internal hosts, TUNNELBOI-managed RDP into the estate), plus new file writes / assembly loads on that server that correlate in time with inbound listener activity (TEMPLEPLAY upload = ingress tooling; download = local-system collection staged for retrieval), and outbound response volume anomalies where collected data is exfiltrated back inside normal-looking HTTP responses. Individually each is explainable; stacked on a passive-listener host (HUNT-01) they are the access-broker hand-off in progress.
- **ATT&CK:**
  - T1090 — Proxy (command-and-control) — TEMPLEPLAY establishes HTTP proxy connections through TEMPLEDOOR to route operator traffic to unreachable internal hosts via the compromised server
  - T1572 — Protocol Tunneling (command-and-control) — TUNNELBOI tunnels remote-access traffic through the compromised environment to reach internal hosts and support access hand-off
  - T1105 — Ingress Tool Transfer (command-and-control) — TEMPLEPLAY uploads additional tooling/payloads through TEMPLEDOOR over the passive channel, often loaded straight into memory
  - T1005 — Data from Local System (collection) — TEMPLEPLAY's file-download reads files of interest from the compromised server's local filesystem
  - T1041 — Exfiltration Over C2 Channel (exfiltration) — collected files are retrieved back to operators inside the same inbound HTTP(S) passive-response channel, blending with normal web responses

- **Actor procedure:** The TEMPLEPLAY .NET controller drives TEMPLEDOOR to (1) establish an HTTP proxy so operators route traffic through the compromised web server to internal hosts behind the boundary, and (2) upload/download files — staging follow-on tooling onto the server and pulling collected local files back. TUNNELBOI is a dedicated network controller that manages RDP connections and remote-host access, tunnelling interactive remote access across the victim environment to move laterally and hand reliable access to downstream Iranian operators (Storm-0861/Scarred Manticore, wiper crews). All of this is wrapped inside the compromised host's normal channels, and exfil returns as ordinary-looking HTTP response traffic — the inbound-only design deliberately limits egress visibility.
- **Why a hunt, not a rule:** there is no discrete signature — proxying and tunnelling ride the server's own legitimate web/RDP channels, file reads by a server process are routine, and exfil is indistinguishable from a large normal HTTP response at the packet level. The base rate of servers making internal connections (patching, monitoring, AD, backups) is far too high for a standalone rule. The durable observable (Summiting Level 3–4: this is behavior-core — the access-broker role *requires* the foothold host to originate internal reach and move data) is *directional and relational*: a host whose role is to receive web requests now initiating RDP/SMB/arbitrary-port connections inward, correlated with the passive-listener activity of HUNT-01 and with new on-disk writes. Establishing "what this server class is *supposed* to originate" and time-correlating listener→pivot→transfer is per-environment baselining and analyst judgement, not a threshold.

## Data sources required

- Network flow (Zeek conn.log / firewall / EDR `DeviceNetworkEvents`) with **direction** — connections *sourced from* the web/edge server to internal RFC1918 hosts, especially RDP/3389, SMB/445, WinRM
- Windows Security EID 4624 type 10 (RemoteInteractive) / 4778 (session reconnect) on internal hosts, with source IP = the compromised server — TUNNELBOI RDP hand-off
- Sysmon EID 11 (file create) / EID 7 (image load) on the server, time-correlated with HUNT-01 listener activity — TEMPLEPLAY upload/download
- Outbound HTTP response byte-volume per session (proxy/web logs, Zeek http.log `response_body_len`) for exfil-volume anomalies against the server's own baseline

## Query starting point

Platform: `Splunk SPL` (directional flow + RDP correlation), then volume anomaly

```
# (a) Web/edge server ORIGINATING internal RDP/SMB — inverted role for a passive-listener host
index=network sourcetype=zeek_conn
| search src_ip IN (<passive_listener_server_ips>) dest_port IN (3389,445,5985,5986)
| where cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip)
| stats dc(dest_ip) as internal_targets values(dest_port) as ports earliest(_time) as first by src_ip
| where internal_targets >= 2      /* fan-out inward = tunnelling/pivot, not a single admin path */
```

```
# (b) Inbound RDP on internal hosts whose SOURCE is the compromised web server (TUNNELBOI)
index=wineventlog EventCode=4624 Logon_Type=10
| search Source_Network_Address IN (<passive_listener_server_ips>)
| stats values(Account_Name) as accounts count by ComputerName, Source_Network_Address

# (c) Exfil-volume anomaly: server HTTP responses >4 stdev over its own 14d baseline
index=web sourcetype=iis OR sourcetype=zeek_http host IN (<passive_listener_server_ips>)
| bin _time span=1h | stats sum(sc_bytes) as resp_bytes by _time, host
| eventstats avg(resp_bytes) as mu stdev(resp_bytes) as sd by host
| where resp_bytes > mu + 4*sd
```

Time-correlate (b)/(c) with HUNT-01 inbound-listener execution and with Sysmon EID 11 file writes on the server (staged upload/collected download) to build the listener→pivot→transfer→exfil chain on one host.

## Triage guidance

- **Likely malicious:** an internet-facing web/SharePoint/IIS server originating RDP or SMB to multiple internal hosts it has no operational reason to reach; internal hosts logging type-10 RDP whose source is that server; a burst of new file writes on the server time-aligned with inbound listener activity followed by an outbound response-volume spike; any of this on a host already flagged by HUNT-01, in the targeted MENA gov/telecom sectors, or overlapping a prior APT34/OilRig compromise.
- **Likely benign / expected:** legitimate jump/management servers and admin tooling that *are* supposed to originate internal RDP/WinRM (baseline and allowlist the source→dest→account triples); backup/patch/monitoring agents making scheduled internal connections; large legitimate downloads/report exports driving response volume on a known cadence. Directionality alone is not enough — the discriminator is a *passive-listener* server (not a designated jump host) originating the reach.
- **Pivot next:** confirm the passive listener on the source server (HUNT-01) and its in-memory loader/driver (HUNT-03/04); enumerate the internal hosts reached (RDP targets, proxied destinations) as the next scope of the intrusion and candidate access hand-off; cross-reference the detection lane for anomalous internal RDP (T1021.001). A live proxy/tunnel from a compromised server into the internal estate is active lateral movement and access brokering — escalate to incident-response-coordinator immediately. The "passive-listener host originates internal RDP" relation is repeatable once the jump-host allowlist is built — hand to detection-engineering (Summiting Level 3).

## References

- https://thehackernews.com/2024/09/iranian-apt-unc1860-linked-to-mois.html
- https://securityaffairs.com/168656/apt/unc1860-provides-iran-linked-apts-access-middle-east.html
- https://attack.mitre.org/techniques/T1090/
- https://attack.mitre.org/techniques/T1572/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1041/
