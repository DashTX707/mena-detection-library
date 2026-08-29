# Hunt: Scarred Manticore FOXSHELL/LIONHEAD proxy, tunnel & EWS relay — internal connections sourced from a web server, and localhost EWS forwarding on Exchange

- **Hypothesis:** If FOXSHELL is proxying/tunnelling through a compromised IIS/SharePoint server, or LIONHEAD is relaying email off an Exchange host, then the tell is a *directionality/relationship anomaly*, not a signature: an Internet-facing web server (`w3wp.exe`/the web-shell worker) that suddenly *originates* internal TCP connections it never made before — especially RDP (3389) or other firewall-blocked services to internal hosts — because the external operator is riding the web channel inbound and the socket to the real target is opened *from* the server; and on Exchange, a rogue forwarder process making `localhost:444 /ews/exchange.asmx` requests whose volume/pattern is decoupled from any legitimate external EWS client.
- **ATT&CK:**
  - T1090 — Proxy (command-and-control) — FOXSHELL (Tunna-derived) lets the operator reach any service on the compromised host, including firewall-blocked ones, tunnelled over the web-shell's own HTTP channel; frequently used to proxy RDP inward
  - T1572 — Protocol Tunneling (command-and-control) — FOXSHELL opens a socket to a config-specified remote machine and relays `Data`-type packages between that socket and the HTTP channel, encapsulating internal TCP (notably RDP) inside HTTP
  - T1090.002 — Proxy: External Proxy (command-and-control) — LIONHEAD on Exchange registers `listen_urls` and forwards each request's content-type/cookie/body to `localhost:444 /ews/exchange.asmx`, returning the EWS response, so external EWS consumption looks like local EWS traffic
- **Actor procedure:** FOXSHELL originates from the open-source Tunna framework (customized to `Tunna v1.1g`) and evolved through XORO, Bsae64, and compiled `App_Web_*.dll` versions. It is a web-shell proxy: the target service IP/port is supplied in a `Config`/`RDPconfig` PackageType, the shell opens a socket to that target, and relays `Data` packages between the socket and the inbound HTTP channel — letting the operator tunnel RDP and other blocked services in over ports 80/443. The compiled `ClientBin.aspx` FOXSHELL was used against the Albanian-government SharePoint server in 2021. LIONHEAD is a tiny web forwarder installed on Exchange servers (same phantom-DLL-hijack install as LIONTAIL): it registers `listen_urls` (e.g. `https://+:443/<redacted>/`), copies content-type/cookie/body from each inbound request, forwards to `forward_server/forward_path/forward_port` = `localhost:444 /ews/exchange.asmx`, and returns the EWS response — bypassing external-EWS restrictions and hiding that the true consumer of the mailbox data is external.
- **Why a hunt, not a rule:** all three techniques deliberately ride the *server's own legitimate channel*. The proxied/tunnelled traffic is wrapped in ordinary HTTP to/from a web server on ports it already serves; the EWS relay terminates on the Exchange host and hits localhost, so from the network it looks like the box talking to itself. There is no external C2 IP, no anomalous port, no payload signature that survives the XOR/base64 wrapping — an IP/port/URI rule is either blind or drowns in legitimate web traffic. The durable observable (Summiting Level 3–4: an unexpected process→network relationship, which the actor cannot drop without abandoning the proxy design) is *a web-worker process becoming a source of internal client connections it has no business making* (a web server that starts speaking RDP outbound to a DC), and *localhost EWS request volume that no external mailbox client accounts for*. Separating that from legitimate admin RDP, health probes, and real EWS load is per-server relationship baselining — analyst work, not a signature.

## Data sources required

- Sysmon EID 3 (network connect) with `Image` = `w3wp.exe` / the web-shell worker / the LIONHEAD forwarder — to catch a web process *initiating* internal connections
- NDR / Zeek / firewall flow logs for internal RDP(3389) and other service connections *sourced from* a web/Exchange server
- IIS logs + Exchange HTTPProxy / EWS logs (localhost `:444 /ews/exchange.asmx` request pattern; correlate against external client identity)
- Exchange mailbox audit / EWS access logs (impersonation, access volume) to corroborate email collection riding the relay

## Query starting point

Platform: `Splunk SPL`

```
index=endpoint source=*Sysmon* EventCode=3
| eval img=lower(Image), dport=DestinationPort, dip=DestinationIp
| where match(img,"(?i)\\\\(w3wp|inetinfo|dllhost)\.exe$") OR match(img,"(?i)ews|edgetransport|exchange")
| eval internal_dst=if(cidrmatch("10.0.0.0/8",dip) OR cidrmatch("172.16.0.0/12",dip)
                        OR cidrmatch("192.168.0.0/16",dip),1,0)
| eval risky_svc=if(dport IN (3389,445,5985,5986,1433,22),1,0)   /* web server should not source these */
| where internal_dst=1 AND risky_svc=1
| stats count values(dport) as ports dc(dip) as n_targets values(dip) as targets
        min(_time) as first by host, img
| where n_targets>=1
| sort - count
```

```
# LIONHEAD localhost EWS relay — Exchange HTTPProxy / EWS logs
index=exchange (sourcetype=*HttpProxy* OR sourcetype=*ews*)
| eval url=lower(cs_uri_stem), client=lower(coalesce(client_ip,c_ip))
| where match(url,"/ews/exchange\.asmx") AND (client="127.0.0.1" OR client="::1" OR client="localhost")
| bin _time span=10m
| stats count values(user) as users dc(url) as uris by _time, host, s_port
| where s_port=444 OR count>50    /* localhost EWS traffic decoupled from external clients */
```

Correlate a web/Exchange host that both *originates* internal RDP (first query) and *hosts a new web shell* (`App_Web_*.dll`/`ClientBin.aspx`/`~/1.aspx`, detection lane) or a phantom-DLL load (HUNT-01/05) in the same window.

## Triage guidance

- **Likely malicious:** `w3wp.exe` (or an unexpected worker) on an Internet-facing IIS/SharePoint server initiating RDP/SMB/WinRM/SQL to internal hosts it never contacted before; an Exchange forwarder making sustained `localhost:444 /ews/exchange.asmx` requests not matched by any external EWS client session; either stacked on a same-host web shell, phantom DLL, or the doubled Exchange URL-prefix from HUNT-01.
- **Likely benign / expected:** legitimate management agents/scripts running under the web identity that do make internal calls (baseline them); real Exchange internal EWS/Autodiscover between roles; genuine external EWS clients (Outlook, mobile, migration tools) — tie localhost EWS volume back to a real authenticated external session before flagging. Admin RDP *to* the web server is normal; RDP *from* it is the anomaly.
- **Pivot next:** identify the web-shell/forwarder process and pivot to HUNT-01 (its URL registration), HUNT-04 (XOR/base64 payloads in the HTTP bodies it relays), and HUNT-05 (masquerade of the forwarder DLL). On Exchange, pull mailbox-audit logs for the accounts whose data the relay is fronting (email collection/exfil, detection lane). A live proxy/tunnel or EWS relay is an active intrusion with lateral movement / data theft in progress — escalate to incident-response-coordinator. The "web-worker sources internal RDP" relationship, once baselined per server, is precise enough to hand to detection-engineering.

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1090/
- https://attack.mitre.org/techniques/T1090/002/
- https://attack.mitre.org/techniques/T1572/
