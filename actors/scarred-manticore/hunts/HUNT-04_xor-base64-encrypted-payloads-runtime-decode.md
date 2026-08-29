# Hunt: Scarred Manticore custom XOR/base64 C2 crypto — high-entropy blobs in HTTP bodies to server endpoints, shared heartbeat strings, and YARA on the XOR-with-first-byte constants

- **Hypothesis:** If a LIONTAIL/FOXSHELL/SDD implant is receiving commands or returning results, then inside otherwise-normal HTTP to/from a compromised server we should find a repeating pattern that no legitimate app produces: request/response bodies that base64-decode to high-entropy content which then XOR-decrypts with its own first byte (the actor's signature "XOR-with-first-byte + base64" scheme), the shared heartbeat exchange (request URL containing `wOxhuoSBgpGcnLQZxipa` answered `UsEPTIkCRUwarKZfRnyjcG13DFA` with 200 OK), and — at rest / in memory — the embedded base64-encoded encryption DLLs (`XORO.dll`, `Base64.dll`) and the shared XOR/obfuscation constants, catchable by YARA on samples and process dumps.
- **ATT&CK:**
  - T1573.001 — Encrypted Channel: Symmetric Cryptography (command-and-control) — LIONTAIL base64-decodes then XORs the whole payload with the first data byte; responses XOR a random key byte prepended before base64; web shells share the scheme (AES additionally in compiled FOXSHELL)
  - T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File (stealth) — configs/payloads stored XOR-encoded; FOXSHELL embeds its encryption module as a base64-encoded .NET DLL inside the web-shell body; WINTAPIX carries an encrypted .NET payload
  - T1027.002 — Obfuscated Files or Information: Software Packing (stealth) — .NET shells/backdoors carry heavy class/method/string obfuscation; the WINTAPIX payload adds a commercial .NET obfuscator on top
  - T1140 — Deobfuscate/Decode Files or Information (stealth) — at runtime the implants reverse their own encoding (base64+XOR) before in-memory execution; SDD base64+XOR-decodes the POST-body `Vet` command and base64-decodes the `Vet` parameter value before `cmd /c`
- **Actor procedure:** C2 bodies are protected by a custom symmetric layer beneath TLS, not TLS alone. LIONTAIL base64-decodes an inbound request then XORs the payload with its first byte; for responses it XOR-encodes with a randomly chosen key byte prepended to the result, then base64-encodes. The web shells (`Tunna v1.1g`, FOXSHELL `XORO`/`Bsae64`, SDD) use the same XOR-with-first-byte(s) scheme, sometimes via embedded encryption DLLs (`XORO.dll`, `Base64.dll`) carried base64-encoded inside the shell body; compiled FOXSHELL adds AES. Configs and payloads are stored XOR-encoded at rest and decoded at runtime immediately before in-memory execution. The whole family shares heartbeat strings (`wOxhuoSBgpGcnLQZxipa` / `UsEPTIkCRUwarKZfRnyjcG13DFA`) — a code-overlap fingerprint Check Point used for attribution.
- **Why a hunt, not a rule:** the custom XOR/base64 layer sits inside ordinary HTTP that is often itself TLS-wrapped, and is *designed* to defeat content inspection — so a payload-content signature has nothing stable to match, and encoded blobs in HTTP bodies have an enormous benign base rate (every API token, cookie, and JSON payload). A byte-string IOC (a specific heartbeat string, a specific hash) is Level 1 and expires the moment the actor rotates it. The value here is twofold: (1) a *behavioral/statistical* hunt — high Shannon entropy in bodies to server endpoints that lack a legitimate encoded-content reason, decoding cleanly under base64→XOR-first-byte — which is analyst-baselined, not alertable; and (2) YARA used *as a hunting tool* over sample repositories and memory dumps for the shared encryption constants and heartbeat strings (Summiting Level 3–4: the shared crypto routine and heartbeat are implementation-core, changed only by re-engineering the framework). A single high-entropy blob is thin; the finding is the blob **decoding under the actor's exact scheme** or **co-locating with the heartbeat / embedded EncryptionDll on a server already flagged by HUNT-01/03**.
- **Why a hunt, not a rule (continued):** YARA is used here for hunting/triage, not as a production detection mechanism.

## Data sources required

- TLS-decrypted or plaintext HTTP request/response bodies to server endpoints (via web-proxy/WAF body capture or full-PCAP where lawful) — for entropy + trial-decode
- File-integrity / sample repository of `.aspx`, `App_Web_*.dll`, and standalone EXEs/DLLs from servers — for static YARA hunting
- Process memory dumps of flagged server processes (from HUNT-03) — for in-memory YARA of decoded content and constants
- IIS/web logs to correlate the heartbeat URL pattern and 200-OK responses

## Query starting point

Platform: `YARA (hunting) + entropy trial-decode procedure`

```yara
rule SM_shared_heartbeat_and_xor_hunt
{
    meta:
        author = "threat-hunter"
        description = "HUNT-ONLY: Scarred Manticore shared heartbeat + encryption-module strings"
        note = "hunting/triage over samples & memory dumps; NOT a production detection rule"
    strings:
        $hb1 = "wOxhuoSBgpGcnLQZxipa" ascii wide
        $hb2 = "UsEPTIkCRUwarKZfRnyjcG13DFA" ascii wide
        $enc1 = "XORO.dll" ascii wide nocase
        $enc2 = "Base64.dll" ascii wide nocase
        $enc3 = "Bsae64" ascii wide           // note the actor's misspelling
        $vet  = "Vet" ascii wide
    condition:
        any of ($hb*) or (2 of ($enc*)) 
}
```

```
# Statistical: high-entropy bodies to server endpoints that decode under base64 -> XOR-first-byte
index=proxy (method=POST OR method=GET) http_content_length>64
| eval body=urldecode(request_body)
| `shannon_entropy(body)`             /* -> entropy field */
| where entropy>4.5 AND match(body,"^[A-Za-z0-9+/=]{32,}$")   /* base64-shaped */
| `b64_then_xor_first_byte(body)`     /* custom cmd: decode; xor all bytes by decoded[0]; return printable_ratio */
| where printable_ratio>0.85          /* decodes cleanly to text/PE -> matches the actor's scheme */
| stats count values(uri_path) as paths values(dest) as servers by src_ip, dest
| where count>=2
```

Scan flagged-server memory dumps (HUNT-03) with the YARA rule; a hit on the heartbeat/EncryptionDll strings in the address space of `w3wp.exe` or a SYSTEM process is high-signal. Trial-decode should be run offline over captured bodies, not inline.

## Triage guidance

- **Likely malicious:** an HTTP body to a server endpoint that base64-decodes then XOR-first-byte-decrypts to a PE/ASCII command; the exact heartbeat request/response pair with 200 OK; an `.aspx`/`App_Web_*.dll` containing a base64-embedded `XORO.dll`/`Base64.dll`; a server process dump containing the heartbeat or `Bsae64` misspelling; an SDD `Vet` POST parameter that base64-decodes to a shell command.
- **Likely benign / expected:** legitimate base64/encoded API payloads, JWTs, cookies, and TLS-inner content that do *not* decode under the XOR-first-byte scheme; genuine `.aspx` apps with no embedded encryption DLL; AES/TLS traffic with no custom layer. The discriminator is *clean decode under the actor's specific scheme* plus co-location with a flagged listener — high entropy alone is not a finding.
- **Pivot next:** tie a decoding body or heartbeat back to the owning process (HUNT-01) and the in-memory loader/driver (HUNT-03); the shared XOR routine + heartbeat is the code-overlap that links samples to WINTAPIX/SDD/FOXSHELL — feed confirmed samples to HUNT-07 for code-similarity attribution. Confirmed decoded C2 on a live host is an incident — escalate to incident-response-coordinator. The shared crypto constants/heartbeat are durable enough that a well-scoped YARA/decode check belongs with detection-engineering for server-content and memory scanning (as a hunt-derived scanner, not a noisy inline alert).

## References

- https://research.checkpoint.com/2023/from-albania-to-the-middle-east-the-scarred-manticore-is-listening/
- https://attack.mitre.org/techniques/T1573/001/
- https://attack.mitre.org/techniques/T1027/013/
- https://attack.mitre.org/techniques/T1027/002/
- https://attack.mitre.org/techniques/T1140/
