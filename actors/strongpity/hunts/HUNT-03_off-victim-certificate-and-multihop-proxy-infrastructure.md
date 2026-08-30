# Hunt: StrongPity — off-victim code-signing/TLS certificates & multi-hop C2 proxy tiers

- **Hypothesis:** If StrongPity's C2 and delivery infrastructure is reachable from our estate, then off-victim it is characterized by **attacker-provisioned certificates** (self-signed / actor code-signing certs on the droppers, and TLS certs on the HTTPS C2) and a **three-tier multi-hop proxy** chain that only ever exposes a first-layer node to the victim — and the on-victim tell is an outbound TLS session to an external host whose certificate and JA3/JARM fingerprint cluster with the actor's known C2, frequently over the non-standard first-tier port. The infrastructure lives entirely on adversary-controlled hosts; the finding is built by *pivoting* from any one weak on-victim observation (an anomalous cert issuer, a JA3 match, egress to a first-tier relay) to the clustered infrastructure, then back to which of our hosts touched it. A single self-signed cert or one odd TLS session is thin — the cluster relationship is the finding.
- **ATT&CK:**
  - T1587.002 — Develop Capabilities: Code Signing Certificates (resource-development) — self-signed/actor code-signing certs on droppers; pivot on cert thumbprint/issuer.
  - T1587.003 — Develop Capabilities: Digital Certificates (resource-development) — TLS/SSL certs provisioned for the HTTPS C2; cluster via CT logs + JA3/JARM.
  - T1584.004 — Compromise Infrastructure: Server (resource-development) — layered upstream C2 servers used to thwart forensics; map the tiers.
  - T1090.003 — Proxy: Multi-hop Proxy (command-and-control) — three-tier relay chain hiding the true operator endpoint; hunt the first-tier node relationship.

- **Actor procedure:** Bitdefender's 2020 whitepaper documented StrongPity's three-tier C2: the victim contacts only a first-layer node, which relays through layered upstream servers (multi-hop proxy) to hide the operators' true endpoint. C2 between the first tier and upstream is protected with SSL/TLS, over the non-standard TCP port 1402. Droppers and components are code-signed with self-signed / actor-controlled certificates to subvert trust (S0491). The layered design and dedicated certs are chosen specifically to defeat forensic pivoting — which is exactly why hunting them requires clustering (cert reuse, JA3/JARM sameness, co-hosting) rather than a single indicator.
- **Why a hunt, not a rule:** The proxy tiers and the servers behind the first hop are on adversary infrastructure and are never visible from the victim — there is nothing on our endpoints to alert on beyond the first-tier contact, which is opaque TLS. Certificate provisioning happens off-victim in CT logs and registrars. A standalone alert on "self-signed code-signing cert" or "JA3 X" drowns in the legitimate long tail (internal PKI, dev tools, countless benign self-signed apps). Real value is the *analyst pivot* — take one weak signal (an anomalous issuer on a binary that also tampered with Defender, a JA3 hit, egress to a suspected relay) and expand it across CT logs / passive DNS / JARM to enumerate the cluster, then see which internal hosts touched any node. If a durable cluster attribute falls out (a reused cert thumbprint, a stable JARM), hand it to detection-engineering as a watchlist — but the actor re-provisions certs and relays, so the hunt rests on the *relationship*, not the value.

## Data sources required

- TLS/network metadata with JA3/JARM fingerprints and server-certificate details (issuer, subject, thumbprint, validity, self-signed flag) — Zeek `ssl.log`/`x509.log`, EDR network events, or firewall TLS inspection
- Code-signing certificate telemetry on executed binaries (EDR `DeviceFileCertificateInfo` / Sysmon signature fields: signer, issuer, thumbprint, trust status)
- External enrichment: Certificate-Transparency logs, passive DNS, and an internet-scan/JARM pivoting source (Censys/Shodan-style) to cluster the C2 tiers
- Egress/proxy logs with destination port (to catch first-tier contact, incl. non-standard ports)

## Query starting point

Platform: `EDR (Microsoft Defender Advanced Hunting / KQL)` — pivot from anomalous signing/TLS certs to the hosts that touched clustered infrastructure

```kusto
// (a) Recently-executed binaries carrying untrusted / self-signed / unknown-issuer signatures
let suspectSigners = DeviceFileCertificateInfo
    | where TimeGenerated > ago(45d)
    | where IsSigned == true and (IsTrusted == false or SignatureType == "SelfSigned")
    | project DeviceName, SHA1, Signer, Issuer, CertificateSerialNumber, Thumbprint = CertificateThumbprint;
// (b) Outbound TLS sessions — surface non-standard-port and repeated small-node contact (first-tier relay behavior)
let egress = DeviceNetworkEvents
    | where TimeGenerated > ago(45d)
    | where RemotePort !in (80,443) or RemotePort == 1402      // 1402 = pack's known first-tier port; keep general
    | where RemoteUrl !endswith ".local"
    | summarize sessions = count(), ports = make_set(RemotePort, 10), firsttime = min(TimeGenerated),
                lasttime = max(TimeGenerated) by DeviceName, RemoteIP, RemoteUrl;
// Correlate: hosts running a suspiciously-signed binary AND making anomalous external TLS egress
suspectSigners
| join kind=inner (egress) on DeviceName
| order by sessions desc
// Then pivot RemoteIP externally: CT-log/JARM cluster the cert + co-hosted domains to map the multi-hop tiers
```

## Triage guidance

- **Likely malicious:** an untrusted/self-signed binary that *also* tampered with Defender exclusions or dropped `%temp%\lang_*` (cross HUNT-05 / detection-pack T1685/T1204.002), whose host then made repeated TLS egress to an external node that JARM/JA3-clusters with — or shares a cert thumbprint / co-hosting with — known StrongPity C2, especially over a non-standard first-tier port. Discovery that the contacted node is a thin relay fronting layered upstreams (open first hop, no legitimate service) is decisive.
- **Likely benign / expected:** self-signed code-signing is heavily used by legitimate internal LOB apps, dev/test builds, and driver/utility vendors — issuer reputation and *behavior* of the signed binary must corroborate before escalation. JA3/JARM collisions are common across shared TLS stacks (many benign apps share a fingerprint); a fingerprint match alone is not attribution. Non-standard-port TLS is used by plenty of legitimate services (VPNs, management planes) — baseline your own before flagging port 1402 or others.
- **Pivot next:** a confirmed cluster relationship → enumerate the full tier map (first-tier relays → upstream servers) via passive DNS/CT/JARM, feed confirmed nodes and cert thumbprints to detection-engineering for watchlisting/blocklisting, and cross-reference every internal host that touched any node. If exfil-consistent egress (volume bursts over the non-standard port) accompanies the contact, escalate to incident-response-coordinator and pivot to the on-host staging/exfil chain (detection-pack T1074.001/T1041/T1571).

## References

- https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf
- https://attack.mitre.org/software/S0491/
- https://attack.mitre.org/techniques/T1587/002/
- https://attack.mitre.org/techniques/T1587/003/
- https://attack.mitre.org/techniques/T1584/004/
- https://attack.mitre.org/techniques/T1090/003/
