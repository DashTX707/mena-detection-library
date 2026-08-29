# Hunt: Gaza Cybergang standard-encoded C2 content (Base64 host data in Spark traffic)

- **Hypothesis:** If the Spark backdoor is beaconing, then network/proxy telemetry (where TLS is absent or terminated for inspection) will show C2 request/response bodies carrying standard-encoded (Base64) blobs — the encoded computer name and host profile — with a beacon-like inter-arrival cadence, on a session whose owning process is a non-browser backdoor rather than a normal web client.
- **ATT&CK:**
  - T1132.001 — Data Encoding: Standard Encoding (command-and-control) — Spark encodes C2 data (e.g. Base64) before transmission
- **Actor procedure:** Spark encodes collected victim data (including the host/computer name and profiling output) with standard encoding before sending it to C2, so the values are not human-readable on the wire and blend with ordinary web parameters. This rides Spark's HTTP/web C2 channel (paired with the encoded/cloud channels in HUNT-01).
- **Why a hunt, not a rule:** Base64 is everywhere in legitimate web traffic — cookies, tokens, JWTs, data URIs, telemetry — so "saw Base64" is not alertable. And where the actor uses TLS or a cloud-SaaS channel the body is opaque to inspection entirely, so the technique is only *sometimes* visible. The value is stacking: high-Base64-ratio bodies **plus** a beacon-like cadence **plus** a non-browser owning process **plus** a decode heuristic that yields a hostname-shaped string — analyst correlation and per-environment tuning, not a fixed match. (Where the channel is the cloud SaaS API instead, the signal lives in HUNT-01, not here.)

## Data sources required

- Proxy / web-gateway logs with request/response body or URI capture (bytes, method, user-agent, host)
- Zeek `http.log` / IDS payload capture (where TLS is not end-to-end) and NetFlow for cadence
- Sysmon EID 3 + EID 1 to attribute the flow to a non-browser process (the load-bearing join)

## Query starting point

Platform: `Splunk SPL`

```
index=proxy OR index=network sourcetype=zeek_http
| eval body=coalesce(uri_query, post_body, uri), blen=len(body)
| where blen > 24
| eval b64chars=len(replace(body,"[^A-Za-z0-9+/=]",""))
| eval b64ratio=round(b64chars/(blen+0.01),2)
| where b64ratio > 0.85 AND like(body,"%=%")=0
| bin _time span=5m
| stats count dc(uri) as uniq_uri avg(blen) as avg_len values(user_agent) as uas
        values(dest) as dests by _time, src, dest
| eventstats avg(count) as mean stdev(count) as sd by src
| where count > 3 AND (uniq_uri < 5 OR count > (mean + 3*sd))
| sort - count
```

## Triage guidance

- **Likely malicious:** high-Base64-ratio request bodies to a low-reputation or newly-seen host with a regular beacon cadence and a small set of repeating URIs; a rare/blank/hard-coded user-agent; the owning process (via Sysmon EID 3 join) is a non-browser binary from `%AppData%`/`%TEMP%`; a decoded blob that resolves to the local hostname/username.
- **Likely benign / expected:** APIs and web apps that legitimately pass Base64 tokens/cookies/JWTs/data-URIs; analytics and ad beacons; software auto-update pings. Baseline by destination + process and allowlist known encoded-token endpoints.
- **Pivot next:** decode a sample body to confirm host-identifying content; resolve the owning process and tie back to initial access (HUNT-07) and discovery (HUNT-02); check whether the same host also uses the cloud-SaaS C2/exfil channel (HUNT-01). A confirmed encoded-hostname beacon to actor infrastructure is a live C2 — escalate.

## References

- https://attack.mitre.org/software/S0543/
- https://unit42.paloaltonetworks.com/molerats-delivers-spark-backdoor/
- https://attack.mitre.org/groups/G0021/
