# Hunt: Infy (Prince of Persia) — off-victim certificate provisioning & DGA-domain/infrastructure acquisition

- **Hypothesis:** If the Infy operator is (re)building takedown-resistant C2 after a sinkhole, then the earliest tell is *off-victim* on adversary infrastructure — freshly provisioned self-signed / attacker-controlled TLS certificates and RSA key material bound to short random-hex domains under `.space` / `.site` / `.top` / `.win` (the Foudre `CRC32("NRV1"+date)` and Tonnerre `NITV1{year}{month}{week}` DGA output), registered against Iranian-nexus registrant/hosting patterns (cf. `aminjalali_58@yahoo.com`). On-victim, the corroborator is a client that, right after a same-shaped DNS resolution, fetches a *small* HTTP(S) "signature file" and only then proceeds — the RSA-authentication step Infy uses so naive sinkholes fail. Neither half alone is a finding: a newly-registered `.site` domain is noise, and a small HTTP GET is noise; a cert-transparency hit on the DGA shape that then appears as a resolved-and-signature-verified C2 for one of *our* hosts is the finding.
- **ATT&CK:**
  - T1587.003 — Digital Certificates (resource-development) — operator provisions self-signed/attacker-controlled TLS certs + RSA keys off-victim to authenticate DGA C2 domains; hunt via certificate-transparency + infra tracking, corroborated by the on-victim signature-file fetch.
  - T1568.002 — Domain Generation Algorithms (command-and-control) — *context/pivot* for the domain shape the certificate is bound to (short random-hex under `.space/.site/.top/.win`). (Detection-lane technique; cited here only as the infrastructure fingerprint that anchors the cert hunt.)
  - T1573.002 — Asymmetric Cryptography (command-and-control) — *context* for the RSA-verified signature-file fetch that is the on-victim half of this correlation. (Detection-lane technique; cited as the on-victim corroborator.)

- **Actor procedure:** After Unit 42 sinkholed Infy's registered C2 in 2016, the operator returned in 2017 with Foudre, which resolves C2 through a DGA (CRC32 hash of `NRV1` + date → `.space/.site/.top` hosts, e.g. `2daa46f1.space`, `ns1/ns2.2daa46f1.space`, `017eab31.space`, `43ec206d.top`) and then **RSA-verifies** the domain/signature file so the client trusts only operator-authenticated infrastructure. Tonnerre (Check Point 2021) extends this with the `NITV1`-form DGA across `.site/.com/.win` and downloads a signature file to validate its HTTP C2 before use. The RSA/cert material and the domains are provisioned on the adversary side ahead of any victim contact — this is the resource-development stage that a defender can watch for *before* the beacon by tracking certificate transparency and passive DNS for the actor's characteristic domain/cert shape.
- **Why a hunt, not a rule:** Certificate/domain provisioning happens entirely off our estate — there is nothing on an endpoint to alert on, and the DGA domain set rotates by date so a static blocklist is stale within a day. The value is in fusing external CT-log / passive-DNS / registrant intel (the actor's domain-and-cert fingerprint) with the thin on-victim signal (a host resolving a same-shaped domain and fetching a tiny signature file). That fusion and the "is this really the Infy shape or a benign CDN cert" judgement is analyst work. If a durable on-victim observable falls out — e.g. a specific process that fetches a <1 KB file from a freshly-CT-logged short-hex `.site` host and gates further execution on it — hand *that* correlation to detection-engineering as a scoped analytic (Summiting: technique-core relational observable, not the ephemeral domain string); do not try to alert on "a certificate was issued."

## Data sources required

- External: certificate-transparency log monitoring (crt.sh / Censys / Shodan) + passive DNS + domain-registration intel, keyed to the DGA fingerprint (short random-hex label; `.space/.site/.top/.win` TLD; newly-registered, low-reputation; Iranian-nexus registrant/hosting overlap).
- DNS resolver logs (Sysmon EID 22 / firewall / Umbrella / Zeek `dns.log`) for internal hosts resolving the domain shape.
- Web-proxy / TLS-metadata (Zeek `ssl.log` + `http.log`, JA3, cert SHA1/issuer/self-signed flag) for the signature-file fetch and the presented C2 certificate.

## Query starting point

Platform: `Splunk SPL` — intersect internal resolutions of the DGA/cert shape with an external CT/TI watchlist, then look for the small signature-file fetch that follows.

```spl
| tstats count min(_time) as first max(_time) as last from datamodel=Network_Resolution
    where nslookup.query_type=A by nslookup.src nslookup.query
| rename nslookup.* as *
| rex field=query "^(?<label>[0-9a-f]{6,12})\.(?<tld>space|site|top|win)$"
| where isnotnull(label)                                            /* short random-hex under actor TLDs */
| lookup ct_watchlist domain AS query OUTPUT ct_issuer ct_selfsigned ct_first_seen
| lookup ti_infra_intel domain AS query OUTPUT registrant asn reputation
| where ct_selfsigned="true" OR reputation="low" OR isnotnull(registrant)
| join type=left src [
    search index=proxy sourcetype=zeek:http method=GET
    | eval body=response_body_len
    | where body>0 AND body<2048                                    /* tiny "signature file" fetch */
    | stats count as sigfetches by src host uri ]
| table src query tld ct_issuer ct_selfsigned registrant asn sigfetches uri first last
| sort - sigfetches
```

## Triage guidance

- **Likely malicious:** an internal host resolves a short random-hex `.space/.site/.win` domain that a CT-log/passive-DNS watchlist shows freshly issued a *self-signed* cert (or Iranian-nexus registrant/hosting overlap), and the same host then GETs a sub-2 KB "signature file" from it before any larger transfer — the Foudre/Tonnerre RSA-authentication handshake; multiple such resolutions on a fixed cadence; ns1/ns2 sub-labels under the same hex parent (as with `2daa46f1.space`).
- **Likely benign / expected:** legitimate services use short domains and self-signed certs (internal test infra, some IoT/CDN edge, dynamic-DNS parents like `strangled.net`/`soon.it` that also appear in benign use); a one-off resolution with no signature-file fetch and no CT/registrant overlap is noise. Baseline your own short-domain resolvers before flagging. Google connectivity checks (`HTTP 200` from `google.com`) are Foudre's own benign-looking probe — presence of *that* immediately before a DGA resolution is a corroborator, not an exclusion.
- **Pivot next:** on a confirmed cert+signature-file match, pull every internal host resolving the same hex-parent and its ns1/ns2 children, extract the presented cert SHA1/JA3 and hunt it estate-wide, and pivot the CT/registrant data to sibling domains for a forward blocklist. If a beacon is confirmed active, this is a live C2 — escalate to incident-response-coordinator and cross-ref the detection-lane C2 hunts (T1071.001 fixed-interval beacon, T1048.003 FTP exfil).

## References

- https://unit42.paloaltonetworks.com/unit42-prince-persia-ride-lightning-infy-returns-foudre/
- https://research.checkpoint.com/2021/after-lightning-comes-thunder/
- https://unit42.paloaltonetworks.com/unit42-prince-of-persia-game-over/
- https://attack.mitre.org/techniques/T1587/003/
- https://attack.mitre.org/techniques/T1568/002/
- https://attack.mitre.org/techniques/T1573/002/
